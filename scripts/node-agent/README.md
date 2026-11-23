# mango-connect node-agent（二期计量：sing-box → 站点 ingest）

逐台自建节点部署本 agent 后，`/admin` 的"本期用量"和用户 dashboard 的流量条
即显示真实字节；配额超限自动停发订阅（401）。本目录交付：

- `agent.py` — 轮询 sing-box `experimental.v2ray_api`（gRPC, reset 模式=增量），
  POST `/ingest/traffic`。仅依赖 `grpcio`（wire format 手写，免 proto 编译）。
- `mango-node-agent.service` — systemd 单元模板。

## 每节点上线 SOP（在生产 sing-box 上执行，先备份再改）

1. **备份**：`cp /etc/sing-box/config.json /etc/sing-box/config.json.bak.$(date +%s)`
2. **确认构建**：`sing-box version` — 需要 `with_v2ray_api` tag（官方发布含；
   自编译则需加 `-tags with_v2ray_api`）。
3. **启用 stats**（`config.json` 顶层）：
   ```json
   "experimental": {
     "v2ray_api": {
       "listen": "127.0.0.1:10085",
       "stats": {"enabled": true, "users": ["<username>", ...]}
     }
   }
   ```
   `users` 列表由站点生成：`users.py gen-node-users <node> --type vless|tuic|anytls`。
4. **加 per-user 凭据**：同一命令的输出即该节点 inbound `users` 数组
   （vless `{name,uuid}` / tuic、anytls `{name,uuid,password}`）。逐个 inbound
   把数组**追加**进 `users`（共享主凭据不动，现存订阅零影响）。
5. **校验并重启**：`sing-box check -c /etc/sing-box/config.json && systemctl restart sing-box`，
   客户端连通性确认后再继续。
6. **登记映射**（站点主机上）：`$SHARE_STATE_DIR/node-credentials.json` 追加
   `{"node": "<池内节点原名>", "key": "<node-name>", "type": "vless|tuic|anytls"}`
   （数组）。渲染器按它把该节点的共享凭据替换为用户独立凭据。
7. **签发 node token**（站点主机上）：`tokens.py add <node-name> --nodes`（明文仅一次）。
8. **装 agent**：拷 `agent.py` + `mango-node-agent.service` 到节点，
   `pip install grpcio`，`install -m755 agent.py /usr/local/bin/mango-node-agent.py`
   （unit 的 ExecStart 固定此路径），env 里填 `AGENT_NODE_NAME/<node-name>`、
   `AGENT_NODE_TOKEN`，`systemctl enable --now mango-node-agent`。
9. **验收**：站点主机 `users.py list` 观察 last fetch；站点 `/admin` 该用户用量随
   客户端流量增长；`traffic-ingest.log` 出现该 node 条目。
10. 逐台重复。全部完成后翻开关：supervisor env 加 `SHARE_PER_USER_YAML=1` 并重启
   ——渲染器即按用户替换凭据（真·独立订阅）；任何 per-user 渲染失败自动回退全局
   渲染（共享凭据仍有效），单用户异常不会影响其他用户。

## 排障

- agent 日志 `grpc error` → sing-box 未开 v2ray_api 或构建缺 tag；
- `401` → node token 错/被吊销；
- 用量不动 → `stats.users` 列表漏了该用户名（用户名须与 inbound `users[].name` 一致）；
- 计数器重启归零是正常语义（reset 模式），丢一个轮询间隔的增量可接受。
