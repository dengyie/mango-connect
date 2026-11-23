#!/usr/bin/env python3
"""SSR page templates for mango-share (visible brand: mango-connect).

Paper-and-ink editorial UI. Every page is self-contained (CSP: no CDN, no
remote fonts, no analytics). Interactive pieces are awesome-ui vanilla
components inlined as classic scripts: UiIcon geometry, ThemeToggle,
StatusIndicator, AnimatedCounter, ToastStack, FluidContourBackdrop. Their
Tailwind classes are mapped onto the local token CSS below because the
credential host cannot load a Tailwind build.

All user data must be escaped before interpolation (_esc / html.escape).
"""

from __future__ import annotations

import base64
import html
import json
import time
from urllib.parse import quote
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import clients
from users import fmt_bytes
from share_constants import public_host as _public_host_default

# Visible brand shown in page chrome and the Quantumult X profile tag.
# Distinct from share_constants.PROFILE_TITLE ('mango-share'), which stays a
# technical identifier on subscription response headers by design.
VISIBLE_BRAND = 'mango-connect'
_BRAND_MARK = '/brand/mango-connect-mark.png'


def public_host() -> str:
    """Public base URL, read lazily: tests re-point SHARE_PUBLIC_HOST per
    case and a module constant would freeze the first import's value."""
    return _public_host_default()


def _esc(v: Any) -> str:
    return html.escape(str(v if v is not None else ''), quote=True)


# ---------------------------------------------------------------------------
# Icons — awesome-ui UiIcon geometry (Tabler Icons conventions, MIT).
# The first block is copied verbatim from awesome-ui/vanilla/UiIcon.js; the
# second block fills glyphs the kit does not ship (home, users, logout, ...)
# drawn on the same 24px / 1.8 stroke Tabler grid. One dict feeds both the
# server-side _icon() and the client-side uiIcon() so markup never drifts.
# ---------------------------------------------------------------------------
_ICONS: Dict[str, str] = {
    'alert-triangle': '<path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z"/>',
    'check': '<path d="m5 12 4 4L19 6"/>',
    'check-circle': '<circle cx="12" cy="12" r="9"/><path d="m8 12 2.5 2.5L16 9"/>',
    'circle-x': '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6m0-6-6 6"/>',
    'clock': '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/>',
    'copy': '<rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    'external-link': '<path d="M14 5h5v5M19 5l-8 8M19 14v3a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h3"/>',
    'globe': '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    'layers': '<path d="m12 3 9 5-9 5-9-5 9-5Zm-9 9 9 5 9-5m-18 4 9 5 9-5"/>',
    'lock': '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    'refresh': '<path d="M20 11a8 8 0 0 0-14.5-4L3 10m0-5v5h5M4 13a8 8 0 0 0 14.5 4L21 14m0 5v-5h-5"/>',
    'search': '<circle cx="10" cy="10" r="7"/><path d="m21 21-6-6"/>',
    'sun': '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2"/>',
    'moon': '<path d="M20 15.5A8 8 0 0 1 8.5 4 8 8 0 0 0 20 15.5Z"/>',
    'monitor': '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
    'user': '<path d="M8 7a4 4 0 1 0 8 0 4 4 0 0 0-8 0"/><path d="M6 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/>',
    'x': '<path d="m6 6 12 12M18 6 6 18"/>',
    'terminal': '<path d="m4 17 6-6-6-6m8 14h8"/>',
    'code': '<path d="m8 9-3 3 3 3m8-6 3 3-3 3M14 5l-4 14"/>',
    'zap': '<path d="M13 3 4 14h7l-1 7 9-11h-7l1-7Z"/>',
    'arrow-right': '<path d="m9 6 6 6-6 6"/>',
    'chevron-down': '<path d="m6 9 6 6 6-6"/>',
    'sliders': '<path d="M4 8h4m4 0h8M4 16h8m4 0h4M8 6v4m8 4v4"/>',
    'plus': '<path d="M12 5v14M5 12h14"/>',
    # -- supplemental glyphs (same Tabler grid) --
    'home': '<path d="M5 12H3l9-9 9 9h-2"/><path d="M5 12v7a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-7"/><path d="M9 21v-6a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v6"/>',
    'users': '<path d="M5 7a4 4 0 1 0 8 0 4 4 0 0 0-8 0"/><path d="M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M21 21v-2a4 4 0 0 0-3-3.85"/>',
    'file-text': '<path d="M14 3v4a1 1 0 0 0 1 1h4"/><path d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2Z"/><path d="M9 9h1m-1 4h6m-6 4h6"/>',
    'logout': '<path d="M14 8V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2-2v-2"/><path d="M9 12h12l-3-3m0 6 3-3"/>',
    'login': '<path d="M15 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7a2 2 0 0 0 2-2v-2"/><path d="M21 12H8l3-3m0 6-3-3"/>',
    'download': '<path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/><path d="m7 11 5 5 5-5M12 4v12"/>',
    'menu': '<path d="M4 6h16M4 12h16M4 18h16"/>',
    'activity': '<path d="M3 12h4l3 8 4-16 3 8h4"/>',
    'shield': '<path d="M12 3a12 12 0 0 0 8.5 3A12 12 0 0 1 12 21 12 12 0 0 1 3.5 6 12 12 0 0 0 12 3"/>',
    'key': '<path d="M16.555 3.843l3.602 3.602a2.877 2.877 0 0 1 0 4.069l-2.643 2.643a2.877 2.877 0 0 1-4.069 0l-.301-.301-6.558 6.558a2 2 0 0 1-1.239.578L5.172 21H4a1 1 0 0 1-.993-.883L3 20v-1.172a2 2 0 0 1 .467-1.284l.119-.13.414-.414h2v-2h2v-2l2.144-2.144-.301-.301a2.877 2.877 0 0 1 0-4.069l2.643-2.643a2.877 2.877 0 0 1 4.069 0z"/><path d="M15 9h.01"/>',
    'history': '<path d="M12 8v4l2 2"/><path d="M3.05 11a9 9 0 1 1 .5 4m-.5 5v-5h5"/>',
    'device-mobile': '<rect x="6" y="3" width="12" height="18" rx="2"/><path d="M11 4h2M12 17v.01"/>',
    'calendar': '<path d="M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7z"/><path d="M16 3v4M8 3v4m-4 4h16"/>',
}


def _icon(name: str, size: int = 16, cls: str = '', label: str = '') -> str:
    """Server-side twin of awesome-ui uiIcon(name, {size, label, className})."""
    aria = f'aria-label="{_esc(label)}" role="img"' if label else 'aria-hidden="true"'
    c = f' class="{_esc(cls)}"' if cls else ''
    return (f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.8" stroke-linecap="round" '
            f'stroke-linejoin="round"{c} {aria}>{_ICONS.get(name, "")}</svg>')


# ---------------------------------------------------------------------------
# Theme — the head script resolves the theme before first paint (no light
# flash in dark mode); ThemeToggle below keeps every toggle instance in sync
# and broadcasts mango-connect-theme-change for the contour backdrop.
# ---------------------------------------------------------------------------
_THEME_STORAGE_KEY = 'mango-connect-theme'
_THEME_HEAD = (
    '<script>try{var m=localStorage.getItem("' + _THEME_STORAGE_KEY + '")||"auto";'
    'document.documentElement.dataset.resolvedTheme='
    '(m==="dark"||(m==="auto"&&matchMedia("(prefers-color-scheme: dark)").matches))'
    '?"dark":"light"}catch(e){document.documentElement.dataset.resolvedTheme='
    'matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"}</script>')

# Buttons are server-rendered (works before JS, testable); the component
# script only hydrates them.
_THEME_TOGGLE = (
    f'<theme-toggle storage-key="{_THEME_STORAGE_KEY}"><div class="theme-toggle" role="group" aria-label="主题切换">'
    + ''.join(f'<button type="button" data-mode="{m}" title="{t}" aria-label="{t}" aria-pressed="false">'
              f'{_icon(ic, 14)}</button>'
              for m, ic, t in (('auto', 'monitor', '跟随系统'), ('light', 'sun', '浅色主题'),
                               ('dark', 'moon', '深色主题')))
    + '</div></theme-toggle>')

# awesome-ui vanilla components, inlined as one classic (non-module) script.
_COMPONENTS_JS = """  <script>
  var UI_ICONS=__ICONS__;
  function uiIcon(name,o){o=o||{};var s=o.size||16,l=o.label||'',c=o.className||'';
    return '<svg width="'+s+'" height="'+s+'" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"'
      +(c?' class="'+c+'"':'')+(l?' role="img" aria-label="'+l+'"':' aria-hidden="true"')+'>'+(UI_ICONS[name]||'')+'</svg>';}

  /* awesome-ui ThemeToggle: auto / light / dark, persisted, multi-instance */
  (function(){
    var root=document.documentElement;
    function resolve(m){return (m==='dark'||(m==='auto'&&matchMedia('(prefers-color-scheme: dark)').matches))?'dark':'light';}
    function apply(key,m){var r=resolve(m);root.dataset.theme=m;root.dataset.resolvedTheme=r;root.style.colorScheme=r;
      var mc=document.querySelector('meta[name="theme-color"]');if(mc)mc.setAttribute('content',r==='dark'?'#171614':'#f6f3ec');
      try{localStorage.setItem(key,m);}catch(e){}
      document.querySelectorAll('theme-toggle [data-mode]').forEach(function(b){
        var on=b.getAttribute('data-mode')===m;b.classList.toggle('is-active',on);b.setAttribute('aria-pressed',on?'true':'false');});
      document.dispatchEvent(new CustomEvent('mango-connect-theme-change',{detail:{mode:m,resolved:r}}));}
    class ThemeToggle extends HTMLElement{
      connectedCallback(){
        this.storageKey=this.getAttribute('storage-key')||'mango-theme';
        var m='auto';try{m=localStorage.getItem(this.storageKey)||'auto';}catch(e){}
        var self=this;
        this.addEventListener('click',function(e){var b=e.target.closest('[data-mode]');if(b)apply(self.storageKey,b.getAttribute('data-mode'));});
        apply(this.storageKey,m);
        var mq=matchMedia('(prefers-color-scheme: dark)');
        if(mq.addEventListener&&!ThemeToggle._mq){ThemeToggle._mq=true;mq.addEventListener('change',function(){
          var cur='auto';try{cur=localStorage.getItem(self.storageKey)||'auto';}catch(e){}if(cur==='auto')apply(self.storageKey,'auto');});}
      }
    }
    if(!customElements.get('theme-toggle'))customElements.define('theme-toggle',ThemeToggle);
  })();

  /* awesome-ui StatusIndicator: online | connecting | busy | error | offline */
  class StatusIndicator extends HTMLElement{
    static get observedAttributes(){return ['status','label','ping-ms','show-dot'];}
    connectedCallback(){this.render();}
    attributeChangedCallback(){if(this.isConnected)this.render();}
    render(){
      var st=this.getAttribute('status')||'online',label=this.getAttribute('label'),ping=this.getAttribute('ping-ms');
      var dot=this.getAttribute('show-dot')!=='false';
      var tone=(st==='connecting'||st==='busy')?'warn':((st==='error'||st==='offline')?'bad':'ok');
      var def={online:'在线',connecting:'连接中',busy:'繁忙',error:'异常',offline:'离线'}[st]||'在线';
      this.innerHTML='<span class="status-pill status-'+tone+'">'
        +(dot?'<span class="status-dot">'+(st==='online'?'<span class="status-ping"></span>':'')+'<span class="status-core"></span></span>':'')
        +'<span>'+(label||def)+'</span>'+(ping!=null?'<span class="status-ms">'+ping+'ms</span>':'')+'</span>';
    }
  }
  if(!customElements.get('status-indicator'))customElements.define('status-indicator',StatusIndicator);

  /* awesome-ui AnimatedCounter: eased count-up once visible */
  (function(){
    var ease=function(t){return 1-Math.pow(1-t,3);};
    var reduced=matchMedia('(prefers-reduced-motion: reduce)').matches;
    class AnimatedCounter extends HTMLElement{
      static get observedAttributes(){return ['target','start','duration','delay','suffix','prefix'];}
      constructor(){super();this._animated=false;this._raf=0;this._to=null;this._obs=null;}
      connectedCallback(){this.classList.add('tabular');this.renderInitial();this.initObserver();}
      disconnectedCallback(){if(this._obs){this._obs.disconnect();this._obs=null;}if(this._to)clearTimeout(this._to);if(this._raf)cancelAnimationFrame(this._raf);}
      attributeChangedCallback(){if(!this.isConnected)return;if(this._animated)this.finish();else this.renderInitial();}
      attr(n,d){return this.getAttribute(n)||d;}
      finish(){this.textContent=this.attr('prefix','')+parseFloat(this.attr('target','0'))+this.attr('suffix','');}
      renderInitial(){this.textContent=this.attr('prefix','')+parseFloat(this.attr('start','0'))+this.attr('suffix','');}
      initObserver(){
        if(this._animated)return;
        var self=this,target=parseFloat(this.attr('target','0')),start=parseFloat(this.attr('start','0'));
        var dur=parseFloat(this.attr('duration','1200')),delay=parseFloat(this.attr('delay','0'));
        var pre=this.attr('prefix',''),suf=this.attr('suffix','');
        if(reduced||typeof IntersectionObserver==='undefined'){this._animated=true;this.finish();return;}
        this._obs=new IntersectionObserver(function(es){es.forEach(function(en){
          if(!en.isIntersecting||self._animated)return;self._animated=true;self._obs.unobserve(en.target);
          self._to=setTimeout(function(){var t0=performance.now(),range=target-start;
            var tick=function(now){var p=Math.min(1,Math.max(0,(now-t0)/dur));
              self.textContent=pre+Math.round(start+ease(p)*range)+suf;
              if(p<1)self._raf=requestAnimationFrame(tick);else self.textContent=pre+target+suf;};
            self._raf=requestAnimationFrame(tick);},delay);});},{threshold:0.2});
        this._obs.observe(this);
      }
    }
    if(!customElements.get('animated-counter'))customElements.define('animated-counter',AnimatedCounter);
  })();

  /* awesome-ui ToastStack: transient feedback, aria-live polite */
  (function(){
    var META={success:'check-circle',error:'circle-x',warning:'alert-triangle',info:'check-circle'};
    function esc(s){return String(s).replace(/[&<>'"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c];});}
    class ToastStack extends HTMLElement{
      constructor(){super();this._t=[];this._timers=new Map();this._seq=0;}
      get duration(){var d=parseInt(this.getAttribute('duration')||'3200',10);return isNaN(d)?3200:d;}
      connectedCallback(){this.setAttribute('aria-live','polite');this.render();}
      push(message,type){var id=++this._seq,self=this;this._t=this._t.concat([{id:id,message:message,type:type||'info'}]);
        if(this.duration>0)this._timers.set(id,setTimeout(function(){self.dismiss(id);},this.duration));this.render();return id;}
      dismiss(id){var tm=this._timers.get(id);if(tm){clearTimeout(tm);this._timers.delete(id);}
        this._t=this._t.filter(function(t){return t.id!==id;});this.render();}
      disconnectedCallback(){this._timers.forEach(function(t){clearTimeout(t);});this._timers.clear();}
      render(){var self=this;
        this.innerHTML=this._t.map(function(t){return '<div class="toast toast-'+esc(t.type)+'" role="status">'
          +uiIcon(META[t.type]||META.info,{size:16,className:'toast-icon'})+'<span class="toast-msg">'+esc(t.message)+'</span>'
          +'<button type="button" class="toast-x" data-toast-id="'+t.id+'" aria-label="关闭提示">'+uiIcon('x',{size:14})+'</button></div>';}).join('');
        this.querySelectorAll('.toast-x').forEach(function(b){b.addEventListener('click',function(){self.dismiss(Number(b.getAttribute('data-toast-id')));});});}
    }
    if(!customElements.get('toast-stack'))customElements.define('toast-stack',ToastStack);
  })();
  function uiToast(msg,type){var s=document.querySelector('toast-stack');if(s&&s.push)s.push(msg,type);}

  /* copy-to-clipboard for any [data-copy-target] button */
  document.addEventListener('click',function(e){
    var b=e.target.closest('[data-copy-target]');if(!b)return;
    var el=document.getElementById(b.getAttribute('data-copy-target'));if(!el)return;
    var v=el.value!=null?el.value:el.textContent;
    var done=function(){var lab=b.querySelector('.btn-label');if(lab){var o=lab.textContent;lab.textContent='已复制';setTimeout(function(){lab.textContent=o;},1600);}
      uiToast(b.getAttribute('data-copy-toast')||'已复制到剪贴板','success');};
    if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(v).then(done,function(){if(el.select){el.select();document.execCommand('copy');}done();});}
    else{if(el.select){el.select();document.execCommand('copy');}done();}
  });
  </script>""".replace('__ICONS__', json.dumps(_ICONS, ensure_ascii=False))

_BACKDROP_JS = (
    "  <script>\n"
    + '''class FluidContourBackdrop extends HTMLElement {
  static get observedAttributes() {
    return ["speed", "interactive", "ink-color", "paper-color"];
  }

  constructor() {
    super();
    this._cleanup = null;
  }

  connectedCallback() {
    this.init();
  }

  disconnectedCallback() {
    if (this._cleanup) {
      this._cleanup();
      this._cleanup = null;
    }
  }

  attributeChangedCallback() {
    if (this.isConnected) {
      this.disconnectedCallback();
      this.init();
    }
  }

  init() {
    this.innerHTML = "";
    const canvas = document.createElement("canvas");
    canvas.setAttribute("aria-hidden", "true");
    canvas.className = "fixed inset-0 pointer-events-none w-full h-full z-0";
    this.appendChild(canvas);

    const gl = canvas.getContext("webgl", {
      alpha: true,
      antialias: false,
      premultipliedAlpha: true,
      powerPreference: "low-power",
    });
    if (!gl) return;

    gl.getExtension("OES_standard_derivatives");

    function compile(type, src) {
      const s = gl.createShader(type);
      if (!s) return null;
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        gl.deleteShader(s);
        return null;
      }
      return s;
    }

    try {
      const vs = compile(gl.VERTEX_SHADER, VERT);
      const fs = compile(gl.FRAGMENT_SHADER, FRAG);
      const prog = gl.createProgram();
      if (!vs || !fs || !prog) return;

      gl.attachShader(prog, vs);
      gl.attachShader(prog, fs);
      gl.linkProgram(prog);
      gl.useProgram(prog);

      const buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(
        gl.ARRAY_BUFFER,
        new Float32Array([-1, -1, 3, -1, -1, 3]),
        gl.STATIC_DRAW
      );

      const aPos = gl.getAttribLocation(prog, "a_pos");
      gl.enableVertexAttribArray(aPos);
      gl.vertexAttribPointer(aPos, 2, gl.FLOAT, false, 0, 0);

      const uRes = gl.getUniformLocation(prog, "u_res");
      const uTime = gl.getUniformLocation(prog, "u_time");
      const uMouse = gl.getUniformLocation(prog, "u_mouse");
      const uInk = gl.getUniformLocation(prog, "u_ink");
      const uPaper = gl.getUniformLocation(prog, "u_paper");

      const speed = parseFloat(this.getAttribute("speed") || "0.035");
      const interactive = this.getAttribute("interactive") !== "false";

      // awesome-ui FluidContourBackdrop: contour ink follows the active theme
      // (paper-ink palette). ThemeToggle flips data-resolved-theme; re-tint the
      // shader on change so dark mode keeps the same subtle texture.
      const applyInk = () => {
        const dark = document.documentElement.dataset.resolvedTheme === 'dark';
        gl.uniform3fv(uInk, dark ? [0.93, 0.90, 0.84] : [0.17, 0.23, 0.19]);
      };
      applyInk();
      document.addEventListener('mango-connect-theme-change', applyInk);

      const dpr = typeof window !== "undefined" ? window.devicePixelRatio || 1 : 1;
      const scale = Math.min(dpr, 2) * 0.75;

      const resize = () => {
        const w = Math.max(1, Math.round(window.innerWidth * scale));
        const h = Math.max(1, Math.round(window.innerHeight * scale));
        if (canvas.width !== w || canvas.height !== h) {
          canvas.width = w;
          canvas.height = h;
          gl.viewport(0, 0, w, h);
          gl.uniform2f(uRes, w, h);
        }
      };

      const mouse = { x: -1e4, y: -1e4, tx: -1e4, ty: -1e4 };

      const onPointerMove = (e) => {
        if (!interactive) return;
        mouse.tx = e.clientX * scale;
        mouse.ty = (window.innerHeight - e.clientY) * scale;
        if (mouse.x < -1e3) {
          mouse.x = mouse.tx;
          mouse.y = mouse.ty;
        }
      };

      const onPointerLeave = () => {
        mouse.tx = -1e4;
        mouse.ty = -1e4;
      };

      window.addEventListener("pointermove", onPointerMove, { passive: true });
      document.documentElement.addEventListener("pointerleave", onPointerLeave);

      const reducedQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
      let t = 17;
      let last = performance.now();
      let raf = 0;

      const draw = () => {
        mouse.x += (mouse.tx - mouse.x) * 0.06;
        mouse.y += (mouse.ty - mouse.y) * 0.06;
        gl.uniform1f(uTime, t);
        gl.uniform2f(uMouse, mouse.x, mouse.y);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
      };

      const loop = (now) => {
        raf = requestAnimationFrame(loop);
        t += Math.min(0.05, (now - last) / 1000) * speed;
        last = now;
        draw();
      };

      const start = () => {
        last = performance.now();
        if (reducedQuery.matches) draw();
        else raf = requestAnimationFrame(loop);
      };

      const stop = () => {
        if (raf) cancelAnimationFrame(raf);
      };

      const onVisibility = () => {
        if (document.hidden) stop();
        else start();
      };

      const onResize = () => {
        resize();
        if (reducedQuery.matches) draw();
      };

      window.addEventListener("resize", onResize);
      document.addEventListener("visibilitychange", onVisibility);

      resize();
      start();

      this._cleanup = () => {
        stop();
        document.removeEventListener('mango-connect-theme-change', applyInk);
        window.removeEventListener("pointermove", onPointerMove);
        document.documentElement.removeEventListener("pointerleave", onPointerLeave);
        window.removeEventListener("resize", onResize);
        document.removeEventListener("visibilitychange", onVisibility);

        if (buf) gl.deleteBuffer(buf);
        if (prog) {
          if (vs) gl.deleteShader(vs);
          if (fs) gl.deleteShader(fs);
          gl.deleteProgram(prog);
        }
      };
    } catch {
      // Fallback
    }
  }
}

if (typeof customElements !== "undefined" && !customElements.get("fluid-contour-backdrop")) {
  customElements.define("fluid-contour-backdrop", FluidContourBackdrop);
}'''
    + "\n  </script>"
).replace('_KEY_', _THEME_STORAGE_KEY)

_APP_JS = """  <script>
  (function(){
    var d=document.querySelector('.mobile-drawer');
    var open=document.getElementById('mobile-menu-button');
    function close(){if(d){d.removeAttribute('open');if(open)open.setAttribute('aria-expanded','false');}}
    if(open&&d)open.addEventListener('click',function(){d.setAttribute('open','');open.setAttribute('aria-expanded','true');
      var f=d.querySelector('.side-nav-button');if(f)f.focus();});
    document.querySelectorAll('.drawer-close').forEach(function(b){b.addEventListener('click',close);});
    document.addEventListener('keydown',function(e){if(e.key==='Escape')close();});
    if(d)d.addEventListener('click',function(e){if(e.target.closest('a'))close();});
  })();
  </script>"""

# ---------------------------------------------------------------------------
# Styles. One token set per theme; the dark set is shared by the explicit
# toggle and the no-JS system fallback so the two can never diverge.
# ---------------------------------------------------------------------------
_DARK_TOKENS = ('color-scheme:dark;--paper:#171614;--paper-2:#1e1c19;--raised:#22201c;--sunken:#12110f;'
                '--ink:#f1ece3;--ink-2:#c3bbae;--ink-3:#8e877c;--line:#34302a;--line-2:#4a443b;'
                '--accent:#f08a4b;--accent-ink:#ffb27e;--accent-wash:#3a2417;--accent-fg:#1a120c;'
                '--ok:#7fd39a;--ok-wash:#17301f;--warn:#f2bf5e;--warn-wash:#352a14;'
                '--bad:#f38b82;--bad-wash:#3a1b18;--shadow:0 1px 0 rgba(0,0,0,.35),0 18px 40px -18px rgba(0,0,0,.6)')

_CSS = """
:root{color-scheme:light;--paper:#f6f3ec;--paper-2:#efeadf;--raised:#fffdf8;--sunken:#ece7db;
--ink:#1f1d1a;--ink-2:#5f5950;--ink-3:#8d867a;--line:#e1dacd;--line-2:#cdc4b5;
--accent:#c2410c;--accent-ink:#9a3412;--accent-wash:#fbe9dc;--accent-fg:#fff;
--ok:#1f7a3d;--ok-wash:#e5f3e8;--warn:#8a5a0b;--warn-wash:#faf0d7;--bad:#b42318;--bad-wash:#fbe6e3;
--shadow:0 1px 0 rgba(60,48,30,.04),0 16px 36px -20px rgba(60,48,30,.28);
--r-sm:8px;--r:12px;--r-lg:18px;
--sans:Inter,-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
--serif:"Iowan Old Style","Palatino Linotype","Songti SC","Noto Serif SC","Source Han Serif SC",Georgia,serif;
--mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace}
:root[data-resolved-theme="dark"]{__DARK__}
@media (prefers-color-scheme:dark){:root:not([data-resolved-theme]){__DARK__}}
*,*::before,*::after{box-sizing:border-box}
*{margin:0}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%}
body{background:var(--paper);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased;min-height:100vh}
a{color:var(--accent-ink);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:3px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:6px}
svg{flex:none;display:block}
code,.mono{font-family:var(--mono);font-size:12.5px}
code{background:var(--sunken);border-radius:6px;padding:1px 6px;word-break:break-all}
.tabular{font-variant-numeric:tabular-nums}
.visually-hidden{position:absolute!important;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}

/* ---- brand ---- */
.brand{display:inline-flex;align-items:center;gap:10px;color:var(--ink);font-weight:720;font-size:14px;letter-spacing:-.02em}
.brand:hover{text-decoration:none}
.brand img{width:30px;height:30px;object-fit:contain}

/* ---- app shell ---- */
.contour-backdrop{display:block;position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.11;mix-blend-mode:multiply}
.contour-backdrop canvas{position:fixed;inset:0;width:100%;height:100%;pointer-events:none}
:root[data-resolved-theme="dark"] .contour-backdrop{opacity:.08;mix-blend-mode:screen}
.app-layout{position:relative;z-index:1;display:grid;grid-template-columns:232px minmax(0,1fr);min-height:100vh}
.sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:22px;padding:24px 14px 18px;border-right:1px solid var(--line);background:color-mix(in srgb,var(--paper) 88%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);overflow-y:auto}
.sidebar>.brand{padding:0 8px}
.sidebar-status{padding:0 8px}
.side-nav-heading{margin:0 10px 6px;color:var(--ink-3);font-size:11px;font-weight:650;letter-spacing:.08em}
.side-nav-group{margin:0;padding:0;list-style:none;display:grid;gap:2px}
.side-nav-group+.side-nav-heading{margin-top:18px}
.side-nav-button{display:flex;width:100%;align-items:center;gap:10px;padding:8px 10px;border:0;border-radius:var(--r-sm);background:transparent;color:var(--ink-2);font:inherit;font-size:13.5px;font-weight:560;text-align:left;cursor:pointer;transition:background .15s,color .15s}
.side-nav-button svg{color:var(--ink-3)}
.side-nav-button:hover{background:var(--paper-2);color:var(--ink);text-decoration:none}
.side-nav-button[aria-current="page"]{background:var(--raised);color:var(--ink);box-shadow:inset 3px 0 0 var(--accent),0 1px 2px rgba(0,0,0,.04)}
.side-nav-button[aria-current="page"] svg{color:var(--accent)}
.sidebar-bottom{margin-top:auto;display:grid;gap:12px;padding:16px 8px 0;border-top:1px solid var(--line)}
.service-caption{color:var(--ink-3);font-size:12px;line-height:1.6}
.sidebar-bottom form .side-nav-button{padding-left:2px}
.content-column{min-width:0;padding:40px clamp(20px,4vw,56px) 96px}
.content-inner{max-width:1080px;margin:0 auto}
.mobile-bar,.mobile-drawer{display:none}
.mobile-drawer[open]{position:fixed;inset:0;z-index:60;display:block;background:rgba(18,16,13,.42)}
.mobile-drawer-summary{display:none}
.mobile-drawer[open] .mobile-drawer-summary{position:absolute;inset:0;display:block;list-style:none}
.mobile-drawer-summary::-webkit-details-marker{display:none}
.mobile-drawer-panel{position:relative;z-index:1;width:min(300px,86vw);height:100%;display:flex;flex-direction:column;gap:22px;padding:20px 16px;background:var(--paper);box-shadow:var(--shadow);overflow-y:auto;animation:drawer-in .2s ease-out}
@keyframes drawer-in{from{transform:translateX(-14px);opacity:.4}to{transform:none;opacity:1}}
.mobile-drawer-top{display:flex;align-items:center;justify-content:space-between}
.drawer-close,.mobile-menu-button{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:36px;padding:0 10px;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--raised);color:var(--ink);font:inherit;font-size:13px;font-weight:600;cursor:pointer}
@media (max-width:900px){
  .app-layout{grid-template-columns:minmax(0,1fr)}
  .sidebar{display:none}
  .content-column{padding:14px 16px 72px}
  .mobile-bar{display:flex;align-items:center;justify-content:space-between;padding:2px 0 20px}
}

/* ---- page head ---- */
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px 24px;flex-wrap:wrap;margin-bottom:26px}
.eyebrow{display:inline-flex;align-items:center;gap:6px;color:var(--ink-3);font-size:12px;font-weight:600;letter-spacing:.06em;margin-bottom:8px}
h1,.display{font-family:var(--serif);font-weight:600;letter-spacing:-.01em;color:var(--ink)}
h1{font-size:clamp(26px,3.2vw,34px);line-height:1.15}
h2{font-size:15px;font-weight:680;letter-spacing:-.005em}
h3{font-size:13.5px;font-weight:650}
.lede{color:var(--ink-2);font-size:14px;margin-top:8px;max-width:62ch}
.page-actions{display:flex;gap:8px;flex-wrap:wrap}
.muted{color:var(--ink-2)}
.faint{color:var(--ink-3);font-size:12.5px}

/* ---- surfaces ---- */
.panel{background:var(--raised);border:1px solid var(--line);border-radius:var(--r-lg);box-shadow:var(--shadow)}
.panel-body{padding:22px 24px}
.panel-head{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 24px;border-bottom:1px solid var(--line)}
.panel-head h2{display:flex;align-items:center;gap:8px}
.panel-head h2 svg{color:var(--accent)}
.panel+.panel,.stack>*+*{margin-top:16px}
.section{padding:20px 24px}
.section+.section{border-top:1px solid var(--line)}
.section-title{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:650;color:var(--ink);margin-bottom:4px}
.section-title svg{color:var(--ink-3)}
.grid-2{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:16px;align-items:start}
.grid-2>.panel+.panel{margin-top:0}
@media (max-width:1100px){.grid-2{grid-template-columns:minmax(0,1fr)}.grid-2>.panel+.panel{margin-top:0}}

/* ---- stats ---- */
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(150px,100%),1fr));gap:12px;margin-bottom:16px}
.stat{background:var(--raised);border:1px solid var(--line);border-radius:var(--r);padding:16px 18px}
.stat-label{display:flex;align-items:center;gap:6px;color:var(--ink-3);font-size:12px;font-weight:600}
.stat-value{font-family:var(--serif);font-size:26px;line-height:1.2;font-weight:600;margin-top:8px;font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.stat-value small{font-family:var(--sans);font-size:13px;font-weight:500;color:var(--ink-2);margin-left:4px}
.stat-note{color:var(--ink-3);font-size:12px;margin-top:4px}
.meter{height:6px;border-radius:99px;background:var(--sunken);overflow:hidden;margin-top:10px}
.meter>span{display:block;height:100%;border-radius:inherit;background:var(--accent);transition:width .6s ease}
.meter.is-over>span{background:var(--bad)}
.meter.is-high>span{background:var(--warn)}

/* ---- buttons & inputs ---- */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;height:36px;padding:0 14px;border-radius:var(--r-sm);border:1px solid var(--line-2);background:var(--raised);color:var(--ink);font:inherit;font-size:13px;font-weight:600;white-space:nowrap;cursor:pointer;transition:background .15s,border-color .15s,transform .05s}
.btn:hover{background:var(--paper-2);text-decoration:none}
.btn:active{transform:translateY(1px)}
.btn-primary{background:var(--ink);border-color:var(--ink);color:var(--paper)}
.btn-primary:hover{background:color-mix(in srgb,var(--ink) 86%,var(--accent))}
.btn-accent{background:var(--accent);border-color:var(--accent);color:var(--accent-fg)}
.btn-accent:hover{background:var(--accent-ink);border-color:var(--accent-ink)}
.btn-ghost{border-color:transparent;background:transparent;color:var(--ink-2)}
.btn-ghost:hover{background:var(--paper-2);color:var(--ink)}
.btn-danger{border-color:color-mix(in srgb,var(--bad) 35%,var(--line));color:var(--bad);background:var(--raised)}
.btn-danger:hover{background:var(--bad-wash)}
.btn-sm{height:30px;padding:0 10px;font-size:12.5px}
.btn-block{width:100%}
.field{display:grid;gap:6px}
.field+.field{margin-top:14px}
.label{font-size:12.5px;font-weight:600;color:var(--ink-2)}
.hint{font-size:12px;color:var(--ink-3)}
.input,input[type=text],input[type=password],input[type=number],input[type=search],select{width:100%;height:38px;padding:0 12px;border:1px solid var(--line-2);border-radius:var(--r-sm);background:var(--paper);color:var(--ink);font:inherit;font-size:14px;transition:border-color .15s,box-shadow .15s}
select{padding-right:28px}
input:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
.input-icon{position:relative}
.input-icon svg{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--ink-3);pointer-events:none}
.input-icon input{padding-left:34px}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px}
.form-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:18px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.toolbar .input-icon{flex:1;min-width:200px}
.copy-field{display:flex;gap:8px;align-items:stretch}
.copy-field input{flex:1;min-width:0;font-family:var(--mono);font-size:12.5px;height:42px;background:var(--sunken)}
.copy-field .btn{height:42px}
@media (max-width:560px){.copy-field{flex-direction:column}}

/* ---- notices ---- */
.notice{display:flex;gap:10px;align-items:flex-start;border-radius:var(--r);padding:12px 14px;font-size:13.5px;line-height:1.6;margin-bottom:14px;border:1px solid transparent}
.notice svg{margin-top:2px}
.notice-ok{background:var(--ok-wash);color:var(--ok);border-color:color-mix(in srgb,var(--ok) 18%,transparent)}
.notice-warn{background:var(--warn-wash);color:var(--warn);border-color:color-mix(in srgb,var(--warn) 20%,transparent)}
.notice-bad{background:var(--bad-wash);color:var(--bad);border-color:color-mix(in srgb,var(--bad) 18%,transparent)}
.notice b,.notice strong{font-weight:700}

/* ---- pills / badges ---- */
.pill{display:inline-flex;align-items:center;gap:5px;height:22px;padding:0 9px;border-radius:99px;font-size:11.5px;font-weight:650;white-space:nowrap}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.pill-ok{background:var(--ok-wash);color:var(--ok)}
.pill-off{background:var(--bad-wash);color:var(--bad)}
.pill-warn{background:var(--warn-wash);color:var(--warn)}
.pill-plain{background:var(--sunken);color:var(--ink-2)}
.pill-plain::before{display:none}
.type-badge{display:inline-flex;align-items:center;height:20px;padding:0 7px;border-radius:6px;background:var(--sunken);color:var(--ink-2);font-family:var(--mono);font-size:11px;font-weight:600;text-transform:lowercase}

/* status-indicator (awesome-ui StatusIndicator, local tokens) */
.status-pill{display:inline-flex;align-items:center;gap:7px;height:26px;padding:0 10px;border-radius:99px;font-size:12px;font-weight:650}
.status-ok{background:var(--ok-wash);color:var(--ok)}
.status-warn{background:var(--warn-wash);color:var(--warn)}
.status-bad{background:var(--bad-wash);color:var(--bad)}
.status-dot{position:relative;display:inline-flex;width:7px;height:7px}
.status-core{position:relative;width:7px;height:7px;border-radius:50%;background:currentColor}
.status-ping{position:absolute;inset:0;border-radius:50%;background:currentColor;opacity:.5;animation:ping 1.8s cubic-bezier(0,0,.2,1) infinite}
.status-ms{font-family:var(--mono);font-size:10.5px;opacity:.75}
@keyframes ping{75%,100%{transform:scale(2.4);opacity:0}}
@media (prefers-reduced-motion:reduce){.status-ping{animation:none}.mobile-drawer-panel{animation:none}}

/* theme-toggle (awesome-ui ThemeToggle, local tokens) */
.theme-toggle{display:inline-flex;gap:2px;padding:3px;border-radius:10px;background:var(--sunken)}
.theme-toggle button{display:grid;place-items:center;width:30px;height:26px;border:0;border-radius:7px;background:transparent;color:var(--ink-3);cursor:pointer}
.theme-toggle button:hover{color:var(--ink)}
.theme-toggle button.is-active{background:var(--raised);color:var(--ink);box-shadow:0 1px 2px rgba(0,0,0,.08)}

/* toast-stack (awesome-ui ToastStack, local tokens) */
toast-stack{position:fixed;right:16px;bottom:16px;z-index:80;display:flex;flex-direction:column;gap:8px;width:min(320px,calc(100vw - 32px))}
.toast{display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:var(--r);background:var(--ink);color:var(--paper);font-size:13px;box-shadow:var(--shadow);animation:toast-in .18s ease-out}
.toast-msg{flex:1;min-width:0}
.toast-success .toast-icon{color:var(--ok)}
.toast-error .toast-icon{color:var(--bad)}
.toast-warning .toast-icon{color:var(--warn)}
.toast-x{display:grid;place-items:center;border:0;background:transparent;color:inherit;opacity:.6;cursor:pointer;padding:2px}
.toast-x:hover{opacity:1}
@keyframes toast-in{from{transform:translateY(6px);opacity:0}to{transform:none;opacity:1}}

/* ---- landing ---- */
.hero{padding:clamp(16px,5vw,56px) 0 8px;max-width:820px}
.hero h1{font-size:clamp(34px,5.4vw,58px);line-height:1.08;letter-spacing:-.02em}
.hero h1 em{font-style:normal;color:var(--accent)}
.hero .lede{font-size:15.5px;margin-top:18px}
.hero-actions{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:28px}
.hero-actions .btn{height:42px;padding:0 18px;font-size:14px}
.figure-row{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0;margin:44px 0 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.figure{padding:20px 4px}
.figure+.figure{border-left:1px solid var(--line);padding-left:22px}
.figure-num{font-family:var(--serif);font-size:clamp(30px,4vw,42px);font-weight:600;line-height:1;font-variant-numeric:tabular-nums}
.figure-cap{color:var(--ink-3);font-size:12.5px;margin-top:8px}
@media (max-width:560px){.figure-row{grid-template-columns:1fr}.figure+.figure{border-left:0;border-top:1px solid var(--line);padding-left:4px}}
.region-badges{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.region-badge{display:inline-flex;align-items:center;gap:8px;height:32px;padding:0 12px;border-radius:99px;background:var(--raised);border:1px solid var(--line);font-size:13px;font-weight:560}
.region-badge .count{color:var(--ink-3);font-size:12px;font-variant-numeric:tabular-nums}
.landing-block{margin-top:48px}
.landing-block>h2{font-family:var(--serif);font-size:20px;font-weight:600}
.flow{list-style:none;padding:0;margin:18px 0 0;display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;counter-reset:flow}
.flow li{counter-increment:flow;padding:18px;border-radius:var(--r);background:var(--raised);border:1px solid var(--line)}
.flow li::before{content:counter(flow,decimal-leading-zero);display:block;font-family:var(--mono);font-size:12px;color:var(--accent);margin-bottom:10px}
.flow strong{display:block;font-size:14px;margin-bottom:4px}
.client-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.client-list span{display:inline-flex;align-items:center;height:30px;padding:0 12px;border-radius:var(--r-sm);background:var(--sunken);color:var(--ink-2);font-size:13px;font-weight:560}

/* ---- dashboard ---- */
.identity{display:flex;align-items:center;gap:14px}
.avatar{display:grid;place-items:center;width:52px;height:52px;border-radius:14px;background:var(--accent-wash);color:var(--accent-ink);font-family:var(--serif);font-size:24px;font-weight:600;text-transform:uppercase;flex:none}
.avatar-sm{width:32px;height:32px;border-radius:9px;font-size:15px}
.meta-line{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:8px}
.primary-action{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;padding:18px;border-radius:var(--r);background:var(--accent-wash)}
.primary-action strong{display:block;font-size:14px;color:var(--ink)}
.primary-action p{color:var(--ink-2);font-size:13px;margin-top:2px}
.client-tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin-top:12px}
.client-tile{display:flex;align-items:center;justify-content:space-between;gap:8px;height:46px;padding:0 14px;border-radius:var(--r);border:1px solid var(--line);background:var(--paper);color:var(--ink);font-weight:600;font-size:13px;transition:border-color .15s,background .15s}
.client-tile svg{color:var(--ink-3);transition:transform .15s,color .15s}
.client-tile:hover{border-color:var(--accent);background:var(--raised);text-decoration:none}
.client-tile:hover svg{color:var(--accent);transform:translate(1px,-1px)}
.client-app{padding:18px 24px}
.client-app+.client-app{border-top:1px solid var(--line)}
.client-app-head{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px}
.client-app-head strong{font-size:15px}
.client-app-head .repo{margin-left:auto;display:inline-flex;align-items:center;gap:5px;color:var(--ink-3);font-size:12.5px}
.client-app>p{margin-top:6px;line-height:1.65}
.dl-rows{display:grid;gap:6px;margin-top:12px}
.dl-row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 10px;padding:8px 10px 8px 14px;border:1px solid var(--line);border-radius:var(--r);background:var(--paper)}
.dl-label{flex:1 1 200px;min-width:0;font-size:13px;font-weight:600}
.dl-size{color:var(--ink-3);font-size:12.5px;font-variant-numeric:tabular-nums}
.sha-list{margin-top:10px}
.sha-list summary{cursor:pointer;color:var(--ink-3);font-size:12.5px}
.sha-list code{display:block;margin-top:6px;padding:6px 8px;border-radius:6px;background:var(--sunken);font-size:11.5px;overflow-wrap:anywhere}
@media (max-width:640px){.client-app{padding:16px 18px}}
.chip-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}
.chip{display:inline-flex;align-items:center;gap:6px;height:30px;padding:0 11px;border-radius:99px;border:1px solid var(--line);background:var(--paper);color:var(--ink-2);font-size:12.5px;font-weight:600}
.chip:hover{color:var(--ink);border-color:var(--line-2);text-decoration:none}
.chip.is-active{background:var(--ink);color:var(--paper);border-color:var(--ink)}
button.chip{font:inherit;font-size:12.5px;font-weight:600;cursor:pointer}
.disclosure{border-top:1px solid var(--line)}
.disclosure summary{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px 24px;cursor:pointer;list-style:none;color:var(--ink-2);font-size:13px;font-weight:600}
.disclosure summary::-webkit-details-marker{display:none}
.disclosure summary svg{transition:transform .2s}
.disclosure[open] summary svg{transform:rotate(180deg)}
.disclosure-body{padding:0 24px 18px;color:var(--ink-2);font-size:13px;line-height:1.75}
.disclosure-body p+p{margin-top:8px}
.danger-zone{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.kv{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;font-size:13px}
.kv dt{color:var(--ink-3)}
.kv dd{margin:0;font-variant-numeric:tabular-nums}

/* ---- nodes ---- */
.node-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:10px}
.node-card{display:grid;gap:10px;padding:14px 16px;border-radius:var(--r);border:1px solid var(--line);background:var(--raised)}
.node-card.is-dead{opacity:.62}
.node-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
.node-name{font-size:13.5px;font-weight:650;line-height:1.4;word-break:break-word}
.node-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--ink-3)}
.latency{display:grid;gap:5px}
.latency-row{display:flex;justify-content:space-between;font-size:12px}
.latency .meter{margin-top:0;height:4px}
.delay-fast{color:var(--ok);font-weight:700}
.delay-mid{color:var(--warn);font-weight:700}
.delay-slow{color:var(--bad);font-weight:700}
.delay-dead{color:var(--ink-3)}
.meter.lat-fast>span{background:var(--ok)}
.meter.lat-mid>span{background:var(--warn)}
.meter.lat-slow>span{background:var(--bad)}
.empty{display:grid;justify-items:center;gap:8px;padding:44px 16px;text-align:center;color:var(--ink-3)}
.empty svg{color:var(--line-2)}
.empty strong{color:var(--ink-2);font-size:14px}

/* ---- docs ---- */
.docs-layout{display:grid;grid-template-columns:200px minmax(0,1fr);gap:28px;align-items:start}
.toc{position:sticky;top:28px;display:grid;gap:2px}
.toc-title{color:var(--ink-3);font-size:11.5px;font-weight:650;letter-spacing:.06em;margin:0 10px 6px}
.toc a{display:block;padding:6px 10px;border-radius:7px;color:var(--ink-2);font-size:13px}
.toc a:hover{background:var(--paper-2);color:var(--ink);text-decoration:none}
.endpoint{display:grid;grid-template-columns:minmax(180px,260px) minmax(0,1fr);gap:6px 20px;padding:14px 24px}
.endpoint+.endpoint{border-top:1px dashed var(--line)}
.endpoint code{align-self:start;justify-self:start;background:var(--sunken)}
.endpoint p{color:var(--ink-2);font-size:13px;line-height:1.7;overflow-wrap:anywhere}
@media (max-width:900px){.docs-layout{grid-template-columns:minmax(0,1fr)}.toc{display:none}}
@media (max-width:640px){.endpoint{grid-template-columns:minmax(0,1fr)}}

/* ---- tables ---- */
.table-wrap{overflow-x:auto;position:relative}
table{width:100%;border-collapse:collapse;font-size:13px}
th{position:sticky;top:0;text-align:left;color:var(--ink-3);font-size:11.5px;font-weight:650;letter-spacing:.04em;padding:10px 12px;border-bottom:1px solid var(--line);background:var(--raised);white-space:nowrap}
td{padding:12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover td{background:color-mix(in srgb,var(--paper-2) 55%,transparent)}
.user-cell{display:flex;gap:10px;align-items:flex-start;min-width:180px}
.user-cell strong{font-size:13.5px}
.user-sub{display:block;color:var(--ink-3);font-size:12px;word-break:break-all}
.row-actions{display:flex;gap:6px;align-items:center;min-width:300px}
.row-actions select{width:auto;height:32px;font-size:12.5px}
.row-actions input{width:110px;height:32px;font-size:12.5px}
.detail-cell{max-width:300px;word-break:break-all;color:var(--ink-3);font-family:var(--mono);font-size:11.5px}

/* ---- narrow (login) ---- */
.auth-wrap{position:relative;z-index:1;min-height:100vh;display:grid;grid-template-rows:auto 1fr auto;padding:22px clamp(16px,4vw,40px)}
.auth-top{display:flex;justify-content:space-between;align-items:center}
.auth-main{display:grid;place-items:center;padding:32px 0}
.auth-card{width:min(400px,100%)}
.auth-card h1{font-size:30px}
.auth-card .panel-body{padding:28px}
.auth-foot{text-align:center;color:var(--ink-3);font-size:12px}
footer.site-foot{margin-top:56px;padding-top:18px;border-top:1px solid var(--line);color:var(--ink-3);font-size:12px;display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
@media (max-width:640px){.panel-body,.section{padding:18px}.panel-head{padding:14px 18px}.disclosure summary{padding:14px 18px}.disclosure-body{padding:0 18px 16px}}
""".replace('__DARK__', _DARK_TOKENS)


# ---------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------
def _brand() -> str:
    return (f'<a class="brand" href="/"><img class="brand-mark" src="{_BRAND_MARK}" '
            f'alt="" width="30" height="30"><span>{VISIBLE_BRAND}</span></a>')


def _page_head(title: str, *, eyebrow: str = '', eyebrow_icon: str = '',
               lede: str = '', actions: str = '', title_html: str = '') -> str:
    eb = (f'<p class="eyebrow">{_icon(eyebrow_icon, 14) if eyebrow_icon else ""}'
          f'{_esc(eyebrow)}</p>') if eyebrow else ''
    ld = f'<p class="lede">{lede}</p>' if lede else ''
    act = f'<div class="page-actions">{actions}</div>' if actions else ''
    return (f'<header class="page-head"><div>{eb}<h1>{title_html or _esc(title)}</h1>{ld}</div>'
            f'{act}</header>')


_NOTICE_ICON = {'ok': 'check-circle', 'warn': 'alert-triangle', 'bad': 'circle-x'}


def _notice(kind: str, text_html: str, icon: str = '') -> str:
    role = 'status' if kind == 'ok' else 'alert'
    return (f'<div class="notice notice-{kind}" role="{role}">'
            f'{_icon(icon or _NOTICE_ICON.get(kind, "alert-triangle"), 16)}'
            f'<div>{text_html}</div></div>')


def _flash(msg: str, err: str) -> str:
    out = ''
    if msg:
        out += _notice('ok', _esc(msg))
    if err:
        out += _notice('bad', _esc(err))
    return out


def _stat(label: str, value_html: str, *, icon: str = '', note: str = '',
          extra: str = '') -> str:
    ic = _icon(icon, 14) if icon else ''
    nt = f'<p class="stat-note">{note}</p>' if note else ''
    return (f'<div class="stat"><p class="stat-label">{ic}{_esc(label)}</p>'
            f'<p class="stat-value">{value_html}</p>{nt}{extra}</div>')


def _counter(n: int, suffix: str = '') -> str:
    s = f' suffix="{_esc(suffix)}"' if suffix else ''
    return f'<animated-counter target="{int(n)}"{s}>{int(n)}{_esc(suffix)}</animated-counter>'


def _meter(pct: float) -> str:
    cls = 'meter is-over' if pct >= 100 else ('meter is-high' if pct >= 85 else 'meter')
    return f'<div class="{cls}" role="presentation"><span style="width:{pct:.1f}%"></span></div>'


def _with_fmt(url: str, fmt: str) -> str:
    return f'{url}{"&" if "?" in url else "?"}fmt={fmt}'


def _client_links(url: str) -> List[Tuple[str, str]]:
    """Deep links per client. Sing-Box, Surge and Quantumult X cannot parse
    Clash YAML, so they get their native format; Shadowrocket's sub:// scheme takes the
    URL base64-encoded (it imports Clash YAML fine)."""
    enc = quote(url, safe='')
    surge = quote(_with_fmt(url, 'surge'), safe='')
    singbox = quote(_with_fmt(url, 'singbox'), safe='')
    qx = 'quantumult-x:///update-remote-profile?remote-resource=' + quote(
        json.dumps({'server_remote': [f'{_with_fmt(url, "qx")}, tag={VISIBLE_BRAND}']},
                   separators=(',', ':'), ensure_ascii=False), safe='')
    rocket = base64.urlsafe_b64encode(url.encode('utf-8')).decode('ascii').rstrip('=')
    return [
        ('Clash / Mihomo', f'clash://install-config?url={enc}'),
        ('Sing-Box', f'sing-box://import-remote-profile?url={singbox}#{quote(VISIBLE_BRAND)}'),
        ('Stash', f'stash://install-config?url={enc}'),
        ('Shadowrocket', f'sub://{rocket}'),
        ('Surge', f'surge:///install-config?url={surge}'),
        ('Quantumult X', qx),
    ]


def _client_tiles(url: str) -> str:
    return '<div class="client-tiles deep-links">' + ''.join(
        f'<a class="client-tile" href="{_esc(href)}"><span>{_esc(name)}</span>'
        f'{_icon("external-link", 15)}</a>' for name, href in _client_links(url)) + '</div>'


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------
def _sidebar(active: str, role: str, logout_csrf: str) -> str:
    """Site navigation, role-aware: 首页 is public; panel pages require a
    session; the 管理 group is admin-only; 登录 shows for anonymous."""
    authed = role in ('user', 'admin')

    def item(href: str, icon: str, label: str, key: str) -> str:
        cur_attr = ' aria-current="page"' if active == key else ''
        return (f'<li class="side-nav-item"><a class="side-nav-button"{cur_attr} '
                f'href="{_esc(href)}">{_icon(icon, 17)}<span>{_esc(label)}</span></a></li>')

    site = item('/', 'home', '首页', 'home')
    if authed:
        site += item('/dashboard', 'user', '用户中心', 'dashboard')
        site += item('/nodes', 'activity', '节点列表', 'nodes')
        site += item('/clients', 'download', '客户端下载', 'clients')
        site += item('/docs', 'file-text', '技术文档', 'docs')
    else:
        site += item('/login', 'login', '登录', 'login')
    groups = f'<p class="side-nav-heading">站点</p><ul class="side-nav-group">{site}</ul>'
    if role == 'admin':
        adm = item('/admin', 'users', '用户管理', 'admin')
        adm += item('/admin/audit', 'history', '审计流水', 'audit')
        groups += f'<p class="side-nav-heading">管理</p><ul class="side-nav-group">{adm}</ul>'

    caption = ('受邀制节点订阅。未获取链接？联系分享者。' if not authed
               else '受邀用户专用。节点与规则与站长自用配置保持一致。')
    logout = ''
    if authed:
        logout = f"""
    <form method="post" action="/logout">
      <input type="hidden" name="csrf" value="{_esc(logout_csrf)}">
      <button type="submit" class="side-nav-button">{_icon('logout', 17)}<span>退出登录</span></button>
    </form>"""
    return f"""
  {_brand()}
  <div class="sidebar-status"><status-indicator status="online" label="服务在线"></status-indicator></div>
  <nav aria-label="站点导航">{groups}</nav>
  <div class="sidebar-bottom">
    <p class="service-caption">{_esc(caption)}</p>
    {_THEME_TOGGLE}{logout}
  </div>"""


def _head(title: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN" data-theme="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#f6f3ec">
<meta name="color-scheme" content="light dark">
<link rel="icon" type="image/png" sizes="192x192" href="{_BRAND_MARK}">
<title>{_esc(title)}</title>
{_THEME_HEAD}
<style>{_CSS}</style>
</head>"""


def _shell(title: str, body: str, *, narrow: bool = False,
           app: bool = False, active: str = '', role: str = 'user',
           logout_csrf: str = '', extra_js: str = '') -> str:
    if narrow:
        return f"""{_head(title)}
<body>
<fluid-contour-backdrop class="contour-backdrop" speed="0.012" interactive="false"></fluid-contour-backdrop>
<div class="auth-wrap">
  <header class="auth-top">{_brand()}</header>
  <main class="auth-main">
{body}
  </main>
  <footer class="auth-foot">{VISIBLE_BRAND} · 受邀订阅 · 未授权访问将被拒绝</footer>
</div>
<toast-stack></toast-stack>
{_COMPONENTS_JS}
{_BACKDROP_JS}
{extra_js}
</body></html>"""
    sidebar = _sidebar(active, role, logout_csrf)
    return f"""{_head(title)}
<body>
<fluid-contour-backdrop class="contour-backdrop" speed="0.012" interactive="false"></fluid-contour-backdrop>
<details class="mobile-drawer">
  <summary class="mobile-drawer-summary" aria-label="关闭侧栏遮罩"></summary>
  <div class="mobile-drawer-panel">
    <div class="mobile-drawer-top">
      <span class="faint">导航</span>
      <button type="button" class="drawer-close" aria-label="关闭侧栏">{_icon('x', 16)}</button>
    </div>
    {sidebar}
  </div>
</details>
<div class="app-layout">
  <aside class="sidebar" aria-label="{VISIBLE_BRAND} 侧栏导航">
  {sidebar}
  </aside>
  <div class="content-column">
    <header class="mobile-bar">
      {_brand()}
      <button type="button" class="mobile-menu-button" id="mobile-menu-button" aria-label="打开侧栏菜单" aria-expanded="false">{_icon('menu', 16)}菜单</button>
    </header>
    <main class="content-inner">
{body}
    </main>
  </div>
</div>
<toast-stack></toast-stack>
{_COMPONENTS_JS}
{_BACKDROP_JS}
{_APP_JS}
{extra_js}
</body></html>"""


def _fmt_date(ts: int) -> str:
    return time.strftime('%Y-%m-%d', time.localtime(ts)) if ts else '—'


def _fmt_ts(ts: int) -> str:
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)) if ts else '—'


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def login_page(csrf: str, error: str = '', username: str = '') -> str:
    banner = _notice('bad', _esc(error)) if error else ''
    body = f"""
  <div class="auth-card">
    <div class="panel"><div class="panel-body">
      <p class="eyebrow">{_icon('lock', 14)}受邀用户</p>
      <h1>登录</h1>
      <p class="lede">登录后管理订阅：查看用量与到期、一键导入客户端、重置密码。</p>
      <div style="margin-top:22px">{banner}</div>
      <form method="post" action="/login">
        <input type="hidden" name="csrf" value="{_esc(csrf)}">
        <div class="field">
          <label class="label" for="f-user">用户名</label>
          <input type="text" id="f-user" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required value="{_esc(username)}"{'' if username else ' autofocus'}>
        </div>
        <div class="field">
          <label class="label" for="f-pass">密码</label>
          <input type="password" id="f-pass" name="password" autocomplete="current-password" required{' autofocus' if username else ''}>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-primary btn-block">登录{_icon('arrow-right', 15)}</button>
        </div>
      </form>
    </div></div>
    <p class="faint" style="margin-top:16px;text-align:center">没有账号？向分享者索取订阅链接或账号；本站不开放注册。<br><a href="/">返回首页</a></p>
  </div>"""
    return _shell(f'{VISIBLE_BRAND} · 登录', body, narrow=True)


_CLIENTS = ('Clash / Mihomo', 'Sing-Box', 'Shadowrocket', 'Stash', 'Surge', 'Quantumult X')


def landing_page(node_count: int, regions: List[Dict[str, Any]],
                 role: str = 'anon', logout_csrf: str = '') -> str:
    """Public landing: editorial hero, public region badges, entry CTAs.
    Uses the app shell so the sidebar is the same site navigation. The
    logout form in the sidebar must carry the session's csrf pair or the
    POST /logout fails double-submit validation for authed visitors."""
    authed = role in ('user', 'admin')
    badge_parts = []
    for r in regions:
        flag_span = (f'<span class="flag">{_esc(r.get("flag") or "")}</span>'
                     if r.get('flag') else '')
        badge_parts.append(f'<span class="region-badge">{flag_span}'
                           f'<span>{_esc(r.get("region") or "")}</span>'
                           f'<span class="count">{int(r.get("count") or 0)} 节点</span></span>')
    badges = ''.join(badge_parts)
    if authed:
        ctas = (f'<a class="btn btn-primary" href="/dashboard">进入用户中心{_icon("arrow-right", 15)}</a>'
                f'<a class="btn" href="/nodes">{_icon("activity", 15)}节点列表</a>')
    else:
        ctas = (f'<a class="btn btn-primary" href="/login">登录{_icon("arrow-right", 15)}</a>'
                '<span class="muted">未获取链接？联系分享者。</span>')
    region_block = (f'<section class="landing-block"><h2>覆盖地区</h2>'
                    f'<div class="region-badges">{badges}</div></section>') if badges else (
                    '<div class="region-badges"></div>')
    clients = ''.join(f'<span>{_esc(c)}</span>' for c in _CLIENTS)
    # The download area is members-only: anonymous visitors get no link.
    install_hint = ('<a href="/clients">客户端下载</a>提供本站镜像与 GitHub 官方链接。' if authed
                    else '登录后在「客户端下载」获取本站镜像与 GitHub 官方链接。')
    dl_btn = (f'<p style="margin-top:14px"><a class="btn" href="/clients">{_icon("download", 15)}下载客户端</a></p>'
              if authed else '')
    body = f"""
  <section class="hero">
    <p class="eyebrow">{_icon('lock', 14)}Private access · 受邀制</p>
    <h1>受邀制节点订阅。<br>配置下载与节点现状，<em>都在用户中心。</em></h1>
    <p class="lede">与站长自用配置逐字节对齐：同一套节点、同一套分流规则，客户端自动按周期更新。</p>
    <div class="hero-actions">{ctas}</div>
  </section>
  <div class="figure-row">
    <div class="figure"><p class="figure-num">{_counter(node_count)}</p><p class="figure-cap">当前分享节点</p></div>
    <div class="figure"><p class="figure-num">{_counter(len(regions))}</p><p class="figure-cap">覆盖地区</p></div>
    <div class="figure"><p class="figure-num">{_counter(5)}</p><p class="figure-cap">订阅格式 · Clash / Sing-Box / Surge / QX / URI</p></div>
  </div>
  {region_block}
  <section class="landing-block">
    <h2>四步接入</h2>
    <ol class="flow">
      <li><strong>获取账号</strong><span class="muted">由分享者开通，本站不开放注册。</span></li>
      <li><strong>安装客户端</strong><span class="muted">{install_hint}</span></li>
      <li><strong>登录用户中心</strong><span class="muted">选择客户端一键导入，或直接下载配置文件。</span></li>
      <li><strong>自动更新</strong><span class="muted">客户端按周期拉取，节点与规则变更自动传导。</span></li>
    </ol>
  </section>
  <section class="landing-block">
    <h2>支持的客户端</h2>
    <div class="client-list">{clients}</div>
    {dl_btn}
    <p class="faint" style="margin-top:12px">共 {int(node_count)} 个节点 · 实际线路以登录后节点状态页为准。</p>
  </section>
  <footer class="site-foot"><span>{VISIBLE_BRAND} · 受邀订阅</span><span>未授权访问将被拒绝</span></footer>"""
    return _shell(f'{VISIBLE_BRAND} · 受邀订阅', body,
                  app=True, active='home', role=role,
                  logout_csrf=logout_csrf)


def _status_banner(reason: str) -> str:
    texts = {
        'disabled': ('bad', '账号已被停用，订阅已停止服务。请联系分享者。'),
        'expired': ('bad', '账号已到期，订阅已停止服务。续期请联系分享者。'),
        'quota_exceeded': ('warn', '本期流量已用完，订阅已暂停。等待下个周期自动恢复，或联系分享者调整配额。'),
    }
    kind, text = texts.get(reason, ('warn', f'服务受限：{_esc(reason)}'))
    return _notice(kind, text)


def _next_reset(reset_day: int) -> str:
    t = time.localtime()
    if t.tm_mday < reset_day:
        ny, nm = t.tm_year, t.tm_mon
    else:
        nm = t.tm_mon + 1
        ny = t.tm_year + (1 if nm > 12 else 0)
        nm = 1 if nm > 12 else nm
    return _fmt_date(int(time.mktime((ny, nm, reset_day, 0, 0, 0, 0, 0, -1))))


def dashboard_page(user: Dict[str, Any], csrf: str, *, status_reason: str = '',
                   masked_url: str = '', sub_url: str = '', sub_kind: str = 'token',
                   node_count: int = 0, last_used: int = 0,
                   export_url: str = '', msg: str = '', err: str = '') -> str:
    quota = int(user.get('quota_bytes') or 0)
    used = int(user.get('used_bytes') or 0)
    if quota > 0:
        pct = min(100.0, used / quota * 100)
        usage_value = f'{_esc(fmt_bytes(used))}<small>/ {_esc(fmt_bytes(quota))}</small>'
        usage_note = f'本期剩余 {_esc(fmt_bytes(max(0, quota - used)))} · 已用 {pct:.0f}%'
        usage_meter = _meter(pct)
    else:
        usage_value = f'{_esc(fmt_bytes(used))}<small>不限量</small>'
        usage_note = '本期累计用量'
        usage_meter = ''
    expire_ts = int(user.get('expire_ts') or 0)
    expire = _fmt_date(expire_ts) if expire_ts else '长期'
    if expire_ts:
        days = int((expire_ts - time.time()) // 86400)
        expire_note = f'剩余 {days} 天' if days >= 0 else '已到期'
    else:
        expire_note = '不设到期'
    cycle = _fmt_date(int(user.get('cycle_start') or 0))
    reset_day = int(user.get('reset_day', 1) or 1)
    next_reset = _next_reset(reset_day)
    is_admin = user.get('role') == 'admin'
    uname = str(user.get('username') or '')

    banner = (_status_banner(status_reason) if status_reason else '') + _flash(msg, err)
    state_pill = ('<span class="pill pill-ok">状态正常</span>' if not status_reason
                  else '<span class="pill pill-warn">服务受限</span>')
    role_pill = f'<span class="pill pill-plain">{"管理员" if is_admin else "成员"}</span>'
    admin_link = (f'<a class="btn" href="/admin">{_icon("users", 15)}管理页</a>'
                  if is_admin else '')
    head = f"""
  <header class="page-head">
    <div class="identity">
      <div class="avatar" aria-hidden="true">{_esc(uname[:1] or '?')}</div>
      <div>
        <p class="eyebrow">用户中心</p>
        <h1>{_esc(uname)}</h1>
        <div class="meta-line">{role_pill}{state_pill}</div>
      </div>
    </div>
    <div class="page-actions">{admin_link}<a class="btn" href="/nodes">{_icon('activity', 15)}节点现状</a></div>
  </header>"""
    fmt_chips = ''.join(
        f'<a class="chip" href="/sub/download?fmt={f}" download>{_icon("download", 13)}{_esc(n)}</a>'
        for f, n in (('singbox', 'Sing-Box JSON'), ('surge', 'Surge CONF'),
                     ('qx', 'Quantumult X'), ('uri', 'URI 列表')))
    stats = ''.join([
        _stat('本期用量', usage_value, icon='activity', note=usage_note, extra=usage_meter),
        _stat('到期时间', _esc(expire), icon='calendar', note=_esc(expire_note)),
        _stat('下次重置', _esc(next_reset), icon='refresh',
              note=f'周期起点 {_esc(cycle)} · 每月 {_esc(user.get("reset_day", 1))} 日'),
        _stat('分享节点', _counter(node_count, ' 个'), icon='globe',
              note=f'最后拉取 {_esc(_fmt_ts(int(last_used)))}'),
    ])
    if sub_kind == 'export':
        sub_note = ('<p class="faint">当前账号使用旧版令牌，此为账号签名 yml 链接（30 天有效，每次登录自动续期）。'
                    '点「重置订阅链接」可换成长期固定链接；重置后旧链接与旧导入地址立即失效。</p>')
    else:
        sub_note = '<p class="faint">长期有效，客户端会按此地址自动更新。泄露后点下方重置，旧链接与旧导入地址立即失效，新链接会显示在这里。</p>'
    sub_block = f"""<p class="muted">你的专属 yml 订阅链接，在客户端里添加即可；请勿外传。</p>
          <div class="copy-field">
            <label class="visually-hidden" for="sub-url">订阅链接</label>
            <input type="text" id="sub-url" readonly value="{_esc(sub_url)}" spellcheck="false">
            <button type="button" class="btn btn-primary" data-copy-target="sub-url" data-copy-toast="订阅链接已复制">{_icon('copy', 15)}<span class="btn-label">复制</span></button>
          </div>
          {sub_note}""" if sub_url else ''
    body = f"""
  {head}
  {banner}
  <div class="stats">{stats}</div>
  <div class="grid-2">
    <section class="panel" id="sub">
      <div class="panel-head"><h2>{_icon('zap', 16)}订阅控制台</h2><span class="faint">与站长自用配置全量对齐</span></div>
      <div class="section">
        <div class="primary-action">
          <div><strong>一键下载配置文件</strong><p>登录态直接导出 yml，无需订阅链接。</p></div>
          <a class="btn btn-accent" href="/sub/download" download>{_icon('download', 15)}下载 yml</a>
        </div>
      </div>
      <div class="section">
        <p class="section-title">{_icon('external-link', 14)}一键导入</p>
        <p class="faint">选择你的客户端，点击即自动导入；客户端会以此地址长期自动更新。</p>
        {_client_tiles(export_url)}
        <p class="faint" style="margin-top:10px">还没装客户端？到 <a href="/clients">客户端下载</a> 获取（本站镜像，国内直连；附 GitHub 官方链接）。</p>
      </div>
      <div class="section">
        <p class="section-title">{_icon('code', 14)}其他格式下载</p>
        <div class="chip-row">{fmt_chips}</div>
      </div>
      <details class="disclosure">
        <summary><span>订阅链接如何生效</span>{_icon('chevron-down', 15)}</summary>
        <div class="disclosure-body">
          <p>一键导入地址长期有效（30 天窗口，每次登录自动续期）；重置订阅链接会立即使旧地址失效，届时请重新登录导入。</p>
          <p>完整订阅链接可随时在右侧「订阅链接」卡片查看和复制（仅本人登录可见）；泄露后点「重置订阅链接」，旧链接随即失效。</p>
          <p>用量由自建节点侧上报累计；第三方机场节点（如有）不受配额约束。</p>
        </div>
      </details>
    </section>
    <div class="stack">
      <section class="panel">
        <div class="panel-head"><h2>{_icon('key', 16)}订阅链接</h2></div>
        <div class="panel-body">
          {sub_block}
          <form method="post" action="/dashboard/regen-token" class="form-actions" onsubmit="return confirm('重置后旧订阅链接立即失效，确认继续？')">
            <input type="hidden" name="csrf" value="{_esc(csrf)}">
            <button type="submit" class="btn btn-danger">{_icon('refresh', 15)}重置订阅链接</button>
          </form>
        </div>
      </section>
      <section class="panel">
        <div class="panel-head"><h2>{_icon('lock', 16)}修改密码</h2></div>
        <div class="panel-body">
          <form method="post" action="/dashboard/password">
            <input type="hidden" name="csrf" value="{_esc(csrf)}">
            <div class="field">
              <label class="label" for="p-old">当前密码</label>
              <input type="password" id="p-old" name="old_password" autocomplete="current-password" required>
            </div>
            <div class="field">
              <label class="label" for="p-new">新密码</label>
              <input type="password" id="p-new" name="new_password" autocomplete="new-password" required minlength="8">
              <span class="hint">至少 8 位</span>
            </div>
            <div class="form-actions"><button type="submit" class="btn btn-primary">更新密码</button></div>
          </form>
        </div>
      </section>
    </div>
  </div>"""
    return _shell(f'{VISIBLE_BRAND} · 用户中心', body,
                  app=True, active='dashboard',
                  role=str(user.get('role') or 'user'), logout_csrf=csrf)


def reveal_page(url: str, *, back: str = '/dashboard',
                title_note: str = '', role: str = 'user',
                logout_csrf: str = '') -> str:
    """Display of a freshly minted subscription URL. The plaintext is never
    persisted; the owner can re-view it on the dashboard (derived token)."""
    note = f'<span class="pill pill-plain">{_esc(title_note)}</span>' if title_note else ''
    body = f"""
  {_page_head('订阅链接已生成', eyebrow='新链接', eyebrow_icon='eye',
              actions=f'<a class="btn" href="{_esc(back)}">{_icon("arrow-right", 15)}返回</a>')}
  {_notice('warn', '新订阅链接已生成，旧链接已失效。请复制保存；之后也可登录用户中心，在「订阅链接」里随时查看。')}
  <section class="panel">
    <div class="panel-head"><h2>{_icon('key', 16)}完整链接</h2>{note}</div>
    <div class="section">
      <div class="copy-field">
        <label class="visually-hidden" for="reveal-url">订阅链接</label>
        <input type="text" id="reveal-url" readonly value="{_esc(url)}" spellcheck="false">
        <button type="button" class="btn btn-primary" id="reveal-copy" data-copy-target="reveal-url" data-copy-toast="订阅链接已复制">{_icon('copy', 15)}<span class="btn-label">复制链接</span></button>
      </div>
    </div>
    <div class="section">
      <p class="section-title">{_icon('external-link', 14)}直接导入客户端</p>
      <p class="faint">导入按钮会唤起对应客户端；也可以手动复制链接，在客户端里手动添加。</p>
      {_client_tiles(url)}
    </div>
  </section>
  <script>
  (function(){{var i=document.getElementById('reveal-url');if(i)i.addEventListener('focus',function(){{i.select();}});}})();
  </script>"""
    return _shell(f'{VISIBLE_BRAND} · 订阅链接', body,
                  app=True, active='', role=str(role or 'user'),
                  logout_csrf=str(logout_csrf or ''))


def _user_row(u: Dict[str, Any], token_info: Optional[Dict[str, Any]], csrf: str) -> str:
    quota = int(u.get('quota_bytes') or 0)
    used = int(u.get('used_bytes') or 0)
    if quota > 0:
        pct = min(100.0, used / quota * 100)
        usage = f'{fmt_bytes(used)} / {fmt_bytes(quota)}'
        bar = _meter(pct)
    else:
        usage = f'{fmt_bytes(used)} / 不限量'
        bar = ''
    if u.get('status') == 'disabled':
        st = '<span class="pill pill-off">停用</span>'
    elif int(u.get('expire_ts') or 0) and time.time() >= int(u['expire_ts']):
        st = '<span class="pill pill-warn">已到期</span>'
    elif quota and used >= quota:
        st = '<span class="pill pill-warn">超限</span>'
    else:
        st = '<span class="pill pill-ok">正常</span>'
    role = ' <span class="pill pill-plain">admin</span>' if u.get('role') == 'admin' else ''
    subs = [f'<span class="user-sub mono">{_esc(u.get("id"))}</span>']
    if u.get('email'):
        subs.append(f'<span class="user-sub">{_esc(u.get("email"))}</span>')
    if u.get('notes'):
        subs.append(f'<span class="user-sub">{_esc(u.get("notes"))}</span>')
    last_used = _fmt_ts(int(token_info.get('last_used') or 0)) if token_info else '—'
    expire = _fmt_date(int(u.get('expire_ts') or 0)) if u.get('expire_ts') else '不限'
    uname = str(u['username'])
    actions = f"""<form method="post" action="/admin/users/{_esc(u['id'])}/action"
      onsubmit="return confirm('确认对该账号执行所选操作？')">
      <input type="hidden" name="csrf" value="{_esc(csrf)}">
      <div class="row-actions">
        <label class="visually-hidden" for="act-{_esc(u['id'])}">操作</label>
        <select name="action" id="act-{_esc(u['id'])}">
          <option value="set-quota">设配额(GB)</option>
          <option value="set-expire">设到期(天数)</option>
          <option value="set-email">设提醒邮箱</option>
          <option value="reset-password">重置密码</option>
          <option value="regen-token">重发订阅</option>
          <option value="disable">停用</option>
          <option value="enable">启用</option>
        </select>
        <input type="text" name="value" placeholder="值" aria-label="操作参数">
        <button type="submit" class="btn btn-sm">执行</button>
      </div>
    </form>"""
    return (f'<tr><td><div class="user-cell"><div class="avatar avatar-sm" aria-hidden="true">'
            f'{_esc(uname[:1])}</div><div><strong>{_esc(uname)}</strong>{role}'
            + ''.join(subs) + '</div></div></td>'
            f'<td>{st}</td><td class="tabular" style="min-width:150px">{_esc(usage)}{bar}</td>'
            f'<td class="tabular">{_esc(expire)}<span class="user-sub">每月 {_esc(u.get("reset_day", 1))} 日重置</span></td>'
            f'<td class="tabular">{_esc(last_used)}</td><td>{actions}</td></tr>')


def _fmt_time_str(v: Any) -> str:
    """Clash history timestamps are ISO strings; render them compactly."""
    if not v:
        return '—'
    return str(v).replace('T', ' ').split('.')[0].split('+')[0]


# Node-pool status -> (label, pill class, delay-cell text when no delay)
_POOL_STATUS = {
    'alive': ('可用', 'pill-ok', '未测'),
    'suspect': ('存疑', 'pill-warn', '探测失败'),
    'dead': ('死亡', 'pill-off', '不可达'),
    'pending': ('检测中', 'pill-plain', '检测中'),
    'unmanaged': ('未纳管', 'pill-plain', '网关未加载'),
}


def _node_status(n: Dict[str, Any]) -> str:
    st = str(n.get('status') or ('alive' if n.get('alive') else 'dead'))
    return st if st in _POOL_STATUS else 'pending'


def _delay_cell(n: Dict[str, Any]) -> str:
    st = _node_status(n)
    delay = n.get('delay')
    if not isinstance(delay, (int, float)) or st in ('dead', 'pending', 'unmanaged'):
        text = _POOL_STATUS[st][2]
        if st == 'suspect' and n.get('fails'):
            text = f'连续失败 {int(n["fails"])} 次'
        return f'<span class="delay-dead">{_esc(text)}</span>'
    cls = 'delay-fast' if delay < 200 else ('delay-mid' if delay < 600 else 'delay-slow')
    return f'<span class="{cls}">{int(delay)} ms</span>'


def _node_card(n: Dict[str, Any]) -> str:
    st = _node_status(n)
    label, pill, _ = _POOL_STATUS[st]
    delay = n.get('delay')
    if st in ('alive', 'suspect') and isinstance(delay, (int, float)):
        tone = 'lat-fast' if delay < 200 else ('lat-mid' if delay < 600 else 'lat-slow')
        width = max(6.0, min(100.0, delay / 10))
        meter = f'<div class="meter {tone}"><span style="width:{width:.0f}%"></span></div>'
    else:
        meter = '<div class="meter"><span style="width:0"></span></div>'
    use = '· 已移出订阅' if st == 'dead' else '· 通过订阅使用'
    return (f'<article class="node-card{" is-dead" if st == "dead" else ""}" data-status="{st}" '
            f'data-name="{_esc(str(n.get("name") or "").lower())}">'
            f'<div class="node-top"><span class="node-name">{_esc(n.get("name"))}</span>'
            f'<span class="pill {pill}">{label}</span></div>'
            f'<div class="latency"><div class="latency-row"><span class="faint">延迟</span>'
            f'{_delay_cell(n)}</div>{meter}</div>'
            f'<div class="node-meta"><span class="type-badge">{_esc(n.get("type"))}</span>'
            f'<span>{"UDP" if n.get("udp") else "TCP"}</span><span>{use}</span></div>'
            f'</article>')


def nodes_page(nodes: List[Dict[str, Any]], error: str, *, active: str = 'nodes',
               role: str = 'user', logout_csrf: str = '',
               aligned: Any = None, aligned_at: str = '') -> str:
    by = {k: [n for n in nodes if _node_status(n) == k] for k in _POOL_STATUS}
    timed = [n for n in by['alive'] if isinstance(n.get('delay'), (int, float))]
    avg = (sum(n['delay'] for n in timed) // len(timed)) if timed else 0
    banner = _notice('warn', f'节点池暂时无法探测：{_esc(error)}（显示的是最近一次结果）') if error else ''
    if aligned is True:
        when = f'（更新于 {_esc(aligned_at)}）' if aligned_at else ''
        banner += _notice('ok', f'与 3x-ui 已对齐{when}')
    elif aligned is False:
        banner += _notice('warn', '与 3x-ui 未对齐——网关配置有更新尚未传导，'
                                  '等待 10 分钟对齐拉取或手动触发。')
    probed = len(by['alive']) + len(by['suspect']) + len(by['dead'])
    health = 'online' if probed and len(by['alive']) == probed else (
        'busy' if by['alive'] else 'offline')
    health_label = {'online': '全部可用', 'busy': '部分可用', 'offline': '暂无可用'}[health]
    stats = ''.join([
        _stat('可用', f'<span id="st-alive">{_counter(len(by["alive"]))}</span>', icon='check-circle',
              extra=f'<status-indicator id="st-health" status="{health}" label="{health_label}" style="display:block;margin-top:8px"></status-indicator>'),
        _stat('存疑', f'<span id="st-suspect">{_counter(len(by["suspect"]))}</span>', icon='alert-triangle',
              note='仍在订阅中，持续复测'),
        _stat('死亡', f'<span id="st-dead">{_counter(len(by["dead"]))}</span>', icon='circle-x',
              note='已移出订阅，每天复活检测'),
        _stat('平均延迟', f'<span id="st-avg">{(_counter(avg) + "<small>ms</small>") if avg else "—"}</span>',
              icon='clock', note=f'可用节点 · 共 <span id="st-total">{len(nodes)}</span> 个'),
    ])
    grid = ''.join(_node_card(n) for n in nodes)
    empty_hidden = ' hidden' if nodes else ''
    body = f"""
  {_page_head('节点现状', eyebrow='节点池', eyebrow_icon='activity',
              lede='站点自维护节点池：每个节点都经网关真实链路（含中继）探测。可用节点每 10 分钟测一次，连续失败 3 次转「存疑」；存疑节点每 30 分钟测一次，连续成功 2 次恢复可用、连续失败 10 次判「死亡」并移出订阅；死亡节点每天复测，测通即回到存疑。「未纳管」是网关未加载的节点（如纯 IPv6），不探测也不移除。本页不含服务器地址与凭据。',
              actions=f'<button type="button" class="btn" id="nodes-refresh">{_icon("refresh", 15)}<span class="btn-label">刷新</span></button>')}
  {banner}
  <div class="stats">{stats}</div>
  <section class="panel">
    <div class="panel-head">
      <div class="toolbar" style="flex:1">
        <div class="input-icon">{_icon('search', 15)}<input type="search" id="node-filter" placeholder="按名称筛选" aria-label="按名称筛选节点"></div>
        <div class="chip-row" style="margin:0" role="group" aria-label="节点状态筛选">
          <button type="button" class="chip is-active" data-filter="all">全部</button>
          <button type="button" class="chip" data-filter="alive">可用</button>
          <button type="button" class="chip" data-filter="suspect">存疑</button>
          <button type="button" class="chip" data-filter="dead">死亡</button>
          <button type="button" class="chip" data-filter="other">未探测</button>
        </div>
      </div>
      <span class="faint" id="nodes-updated">已加载</span>
    </div>
    <div class="panel-body">
      <div class="node-grid" id="nodes-grid">{grid}</div>
      <div class="empty" id="nodes-empty"{empty_hidden}>{_icon('layers', 32)}<strong>没有匹配的节点</strong><span>调整筛选条件，或稍后刷新。</span></div>
    </div>
  </section>"""
    js = """
  <script>
  (function(){
    var grid=document.getElementById('nodes-grid'),empty=document.getElementById('nodes-empty');
    var q=document.getElementById('node-filter'),upd=document.getElementById('nodes-updated');
    var mode='all';
    var ST={alive:['可用','pill-ok','未测'],suspect:['存疑','pill-warn','探测失败'],dead:['死亡','pill-off','不可达'],
      pending:['检测中','pill-plain','检测中'],unmanaged:['未纳管','pill-plain','网关未加载']};
    function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
    function status(n){var s=n.status||(n.alive?'alive':'dead');return ST[s]?s:'pending';}
    function timed(n){var s=status(n);return (s==='alive'||s==='suspect')&&typeof n.delay==='number';}
    function delayHtml(n){
      var s=status(n);
      if(!timed(n)){var t=(s==='suspect'&&n.fails)?('连续失败 '+n.fails+' 次'):ST[s][2];
        return '<span class="delay-dead">'+esc(t)+'</span>';}
      var c=n.delay<200?'delay-fast':(n.delay<600?'delay-mid':'delay-slow');
      return '<span class="'+c+'">'+n.delay+' ms</span>';
    }
    function meter(n){
      if(!timed(n))return '<div class="meter"><span style="width:0"></span></div>';
      var t=n.delay<200?'lat-fast':(n.delay<600?'lat-mid':'lat-slow');
      return '<div class="meter '+t+'"><span style="width:'+Math.max(6,Math.min(100,n.delay/10)).toFixed(0)+'%"></span></div>';
    }
    function card(n){
      var s=status(n);
      return '<article class="node-card'+(s==='dead'?' is-dead':'')+'" data-status="'+s+'" data-name="'+esc(String(n.name||'').toLowerCase())+'">'
        +'<div class="node-top"><span class="node-name">'+esc(n.name)+'</span>'
        +'<span class="pill '+ST[s][1]+'">'+ST[s][0]+'</span></div>'
        +'<div class="latency"><div class="latency-row"><span class="faint">延迟</span>'+delayHtml(n)+'</div>'+meter(n)+'</div>'
        +'<div class="node-meta"><span class="type-badge">'+esc(n.type)+'</span><span>'+(n.udp?'UDP':'TCP')+'</span><span>'
        +(s==='dead'?'· 已移出订阅':'· 通过订阅使用')+'</span></div></article>';
    }
    function match(st){
      if(mode==='all')return true;
      if(mode==='other')return st==='pending'||st==='unmanaged';
      return st===mode;
    }
    function applyFilter(){
      if(!grid)return;var term=(q&&q.value||'').trim().toLowerCase(),shown=0;
      grid.querySelectorAll('.node-card').forEach(function(el){
        var ok=match(el.dataset.status)&&(!term||el.dataset.name.indexOf(term)!==-1);
        el.hidden=!ok;if(ok)shown++;});
      if(empty)empty.hidden=shown>0;
    }
    function setNum(id,v,suf){var el=document.getElementById(id);if(!el)return;
      el.innerHTML=v?(String(v)+(suf?'<small>'+suf+'</small>':'')):'—';}
    function render(nodes){
      if(!grid)return;grid.innerHTML=nodes.map(card).join('');
      var c={alive:0,suspect:0,dead:0};nodes.forEach(function(n){var s=status(n);if(s in c)c[s]++;});
      var live=nodes.filter(function(n){return status(n)==='alive'&&typeof n.delay==='number';});
      var avg=live.length?Math.floor(live.reduce(function(a,n){return a+n.delay;},0)/live.length):0;
      setNum('st-alive',c.alive||'0');setNum('st-suspect',c.suspect||'0');setNum('st-dead',c.dead||'0');
      setNum('st-avg',avg,'ms');var tt=document.getElementById('st-total');if(tt)tt.textContent=nodes.length;
      var h=document.getElementById('st-health'),probed=c.alive+c.suspect+c.dead;
      if(h){var st=probed&&c.alive===probed?'online':(c.alive?'busy':'offline');
        h.setAttribute('label',st==='online'?'全部可用':(st==='busy'?'部分可用':'暂无可用'));h.setAttribute('status',st);}
      applyFilter();
    }
    function stamp(){var d=new Date();if(upd)upd.textContent='更新于 '+String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0')+':'+String(d.getSeconds()).padStart(2,'0');}
    function refresh(manual){
      return fetch('/nodes/api',{credentials:'same-origin'})
        .then(function(r){return r.json();})
        .then(function(d){if(d&&d.ok){render(d.nodes||[]);stamp();if(manual)uiToast('节点状态已刷新','success');}
          else if(manual)uiToast('节点池暂时不可用','warning');})
        .catch(function(){if(manual)uiToast('刷新失败，请稍后重试','error');});
    }
    var b=document.getElementById('nodes-refresh');
    if(b)b.addEventListener('click',function(){b.disabled=true;refresh(true).then(function(){b.disabled=false;});});
    if(q)q.addEventListener('input',applyFilter);
    document.querySelectorAll('[data-filter]').forEach(function(c){c.addEventListener('click',function(){
      mode=c.getAttribute('data-filter');
      document.querySelectorAll('[data-filter]').forEach(function(x){x.classList.toggle('is-active',x===c);});
      applyFilter();});});
    setInterval(function(){if(!document.hidden)refresh(false);},15000);
  })();
  </script>"""
    return _shell(f'{VISIBLE_BRAND} · 节点现状', body,
                  app=True, active=active, role=role,
                  logout_csrf=logout_csrf, extra_js=js)


_DOC_SECTIONS: Sequence[Tuple[str, str, Sequence[Tuple[str, str]]]] = (
    ('formats', '订阅端点与格式', (
        ('GET /sub/<token>', 'Clash / Mihomo YAML（默认）。全部节点与规则为网关客户端导出的字节级镜像。'),
        ('GET /sub/<token>?fmt=singbox', 'Sing-Box JSON（1.12+ 新版 schema：策略组、中继链 detour、规则集全量转换；vless/vmess/trojan/ss/anytls/tuic/hysteria2/http/socks5，mieru 无对应自动省略）。'),
        ('GET /sub/<token>?fmt=surge', 'Surge CONF（托管配置，策略组/中继 underlying-proxy/规则全量转换；ss/vmess/trojan/http/socks5/tuic/hysteria2，vless/anytls/mieru 无 Surge 对应自动省略）。'),
        ('GET /sub/<token>?fmt=qx', 'Quantumult X（server_local + 策略组 + filter_local 规则；ss/vmess/trojan/http/socks5，中继链与 reality 节点省略）。'),
        ('GET /sub/<token>?fmt=uri', 'URI 列表（v2rayN 风格 base64，vless/vmess/trojan/ss/hysteria2/tuic/anytls）。'),
    )),
    ('auth', '导出认证模型', (
        ('下载 /sub/download', '登录会话直接导出 yml/JSON，不需要订阅链接，文件名带用户名。'),
        ('签名导出 /sub/export?u&e&k&s', '客户端 App 无法登录——使用 HMAC(secret.key, export:uid:exp:token_id) 签名链接，30 天窗口且每次登录自动续期；重置订阅链接换 token_id 即全废，深链泄露可即时吊销。'),
        ('token /sub/<token>', '长期订阅凭据：SHA-256 存储、show-once 展示、重置即失效。'),
    )),
    ('align', '对齐机制（与 3x-ui）', (
        ('字节镜像', 'full 模式 /sub 输出 = gateway 客户端导出逐字节复制（mixed-port/tun/dns 与站长自用一致）；仅在节点池有死亡节点时去掉这些节点及其策略组成员。'),
        ('10 分钟对齐拉取', 'cron 触发 gateway /sub/clash 重生成（指纹不变秒回），面板改节点/规则后 ≤10 分钟自动传导。'),
        ('边界', 'rules-reconciler 的 user-rules 只进网关运行时，不进客户端导出（站长自用设备同样如此）。'),
    )),
    ('status', '节点状态数据', (
        ('/nodes/api', '站点自维护节点池（可用/存疑/死亡/未纳管），经网关 controller 逐节点真实链路探测；死亡节点自动移出订阅。只含名称/协议/延迟/状态，永不含 server 地址与凭据。'),
        ('节点池状态机', '可用 10 分钟/次，连续 3 次失败→存疑；存疑 30 分钟/次，连续 2 次成功→可用，连续 10 次失败→死亡；死亡每天复测，成功→存疑。失败需两次尝试确认，网关侧故障触发熔断不计数；剔除后少于 25% 时不剔除。'),
        ('对齐徽章', '与 3x-ui 对齐状态 = 本站输出 sha256 与 gateway mango-clash.meta.json 比对。'),
    )),
    ('clients', '客户端下载镜像', (
        ('GET /clients', '登录后可见（未登录 303 到 /login，侧栏与首页对匿名访客不出现入口）：按平台列出推荐客户端（Clash Verge Rev / FlClash / Clash Meta for Android / sing-box / v2rayN / v2rayNG）与 iOS App Store 客户端，每个安装包给出本站镜像与 GitHub 官方下载两个入口。'),
        ('镜像同步', 'scripts/client-mirror.py 在下载站侧每 6 小时读取各项目 GitHub latest release，按目录逐字节镜像到版本化路径（新版本 = 新路径，CDN 无需清缓存），校验大小与 GitHub sha256 digest 后原子落盘，每个应用保留最近 2 个版本。'),
        ('manifest.json', '镜像清单（版本/文件/大小/sha256/镜像与 GitHub 链接），本站每 10 分钟拉取并持久化；镜像链接必须位于清单目录下、GitHub 链接必须属于对应仓库，否则丢弃。清单缺失时页面自动回落到 GitHub 发布页。'),
    )),
    ('ops', '运维端点', (
        ('GET /health', '存活/节点数/scope/对齐状态（无鉴权，无敏感信息）。'),
        ('state_backup.py pack', '全状态 tar 包（排除 backups/logs），供容器回收前离线拷贝。'),
        ('bootstrap.sh', 'Bohrium 容器重建后一键恢复运行时（目录/权限/supervisor/cron）。'),
    )),
)


_PLATFORM_ICON = {'android': 'device-mobile', 'ios': 'device-mobile'}


def _dl_row(app: Dict[str, Any], f: Dict[str, Any]) -> str:
    m = f.get('mirror')
    if m:
        size = clients.fmt_size(int(m['size']))
        btns = (f'<a class="btn btn-sm btn-primary" href="{_esc(m["url"])}" rel="noopener">'
                f'{_icon("download", 14)}镜像下载</a>'
                f'<a class="btn btn-sm" href="{_esc(m["github_url"])}" rel="noopener noreferrer">'
                f'GitHub{_icon("external-link", 13)}</a>')
    else:
        size = ''
        btns = (f'<a class="btn btn-sm" href="{_esc(app["releases_url"])}" rel="noopener noreferrer">'
                f'{_icon("download", 14)}GitHub 发布页{_icon("external-link", 13)}</a>')
    sz = f'<span class="dl-size">{_esc(size)}</span>' if size else ''
    return f'<div class="dl-row"><span class="dl-label">{_esc(f["label"])}</span>{sz}{btns}</div>'


def _client_app(app: Dict[str, Any]) -> str:
    rec = '<span class="pill pill-ok">推荐</span>' if app.get('recommended') else ''
    hint = f'<p class="faint">导入方式：{_esc(clients.FORMAT_HINT.get(app["fmt"], ""))}</p>'
    if app['store']:
        return (f'<div class="client-app"><div class="client-app-head"><strong>{_esc(app["name"])}</strong>'
                f'{rec}<span class="pill pill-plain">{_esc(app["price"])}</span></div>'
                f'<p class="muted">{_esc(app["blurb"])}</p>{hint}'
                f'<div class="dl-rows"><div class="dl-row"><span class="dl-label">App Store（美区等非国区）</span>'
                f'<a class="btn btn-sm btn-primary" href="{_esc(app["url"])}" rel="noopener noreferrer">'
                f'App Store{_icon("external-link", 13)}</a></div></div></div>')
    ver = ''
    if app.get('version'):
        date = f' · {app["published"]}' if app.get('published') else ''
        ver = f'<span class="pill pill-plain">v{_esc(app["version"])}{_esc(date)}</span>'
    rows = ''.join(_dl_row(app, f) for f in app['files'])
    shas = [(f['mirror']['name'], f['mirror']['sha256']) for f in app['files'] if f.get('mirror')]
    sha_block = ''
    if shas:
        sha_block = ('<details class="sha-list"><summary>SHA-256 校验值</summary>'
                     + ''.join(f'<code>{_esc(h)}  {_esc(n)}</code>' for n, h in shas)
                     + '</details>')
    return (f'<div class="client-app"><div class="client-app-head"><strong>{_esc(app["name"])}</strong>'
            f'{rec}{ver}<a class="repo" href="{_esc(app["repo_url"])}" rel="noopener noreferrer">'
            f'源码仓库{_icon("external-link", 13)}</a></div>'
            f'<p class="muted">{_esc(app["blurb"])}</p>{hint}'
            f'<div class="dl-rows">{rows}</div>{sha_block}</div>')


_ANDROID_GUIDE = (
    ('选哪个安装包', '近几年的手机选 <code>arm64-v8a</code>；不确定架构就选「通用包 universal」（体积大一些，任何手机都能装）；'
                 'armeabi-v7a 只给老旧 32 位机型，x86_64 只给模拟器 / Chromebook。'),
    ('允许安装', '下载完成后在通知栏或「文件管理 · 下载」里点开 APK，按提示允许浏览器「安装未知应用」；'
               '小米 / 华为 / OPPO / vivo 的「纯净模式 / 安全守护」拦截时选「继续安装」或临时关闭。'),
    ('首次连接', '在客户端里导入订阅并开启代理时，系统会弹出「网络连接请求（VPN）」，点「确定」。'),
    ('防止掉线', '在系统「电池 / 应用启动管理」里把客户端设为「不限制」或允许后台运行，避免锁屏后被杀进程断网。'),
    ('系统要求', 'FlClash / v2rayNG / sing-box 需 Android 7 及以上；Android 5–6 旧机请用 Clash Meta for Android '
               '或 sing-box「Android 5–6 旧系统」通用包；华为 HarmonyOS NEXT（纯血鸿蒙）无法安装 APK。'),
)


_ANDROID_TIP = ('<div class="client-app"><p class="muted" style="margin:0">选包：近几年的手机选 <code>arm64-v8a</code>，'
                '不确定就选「通用包 universal」；安装与防掉线步骤见本节末尾<a href="#android-guide">「Android 安装指引」</a>。</p></div>')


def _android_guide() -> str:
    steps = ''.join(f'<li><strong>{_esc(t)}</strong><span class="muted">{d}</span></li>'
                    for t, d in _ANDROID_GUIDE)
    return (f'<div class="client-app" id="android-guide"><div class="client-app-head"><strong>Android 安装指引</strong></div>'
            f'<ol class="flow" style="margin-top:0">{steps}</ol></div>')


def clients_page(manifest: Dict[str, Any], *, mirror_enabled: bool = False,
                 role: str = 'user', logout_csrf: str = '', device: str = '') -> str:
    """Members-only client download page: catalog grouped by platform, mirror
    links from the download-site manifest, GitHub as fallback/alternative.
    `device` ('android' / 'ios', from the User-Agent) moves that platform to
    the top so a phone visitor lands on their own installers."""
    view = clients.platform_view(manifest)
    if device and any(p['key'] == device for p in view):
        view.sort(key=lambda p: p['key'] != device)
    gen = float(manifest.get('generated') or 0)
    if manifest.get('apps'):
        status = _notice('ok', f'镜像同步于 {_esc(_fmt_ts(int(gen)))}：安装包与 GitHub 官方 release '
                               '逐字节一致，可展开「SHA-256 校验值」核对。镜像国内直连，GitHub 链接为官方原址。')
    elif mirror_enabled:
        status = _notice('warn', '镜像暂不可用，下方链接指向各项目 GitHub 官方发布页。')
    else:
        status = ''
    nav = ''.join(f'<a class="chip{" is-active" if p["key"] == device else ""}" href="#p-{p["key"]}">'
                  f'{_icon(_PLATFORM_ICON.get(p["key"], "monitor"), 13)}{_esc(p["label"])}</a>'
                  for p in view)
    sections = []
    for p in view:
        picks = [a['name'] for a in p['apps'] if a.get('recommended')]
        bits = (['已按你的设备置顶'] if device and p['key'] == device else []) \
            + ([f'推荐 {" / ".join(picks)}'] if picks else [])
        note = f'<span class="faint">{_esc(" · ".join(bits))}</span>' if bits else ''
        extra = ''
        lead = _ANDROID_TIP if p['key'] == 'android' else ''
        if p['key'] == 'android':
            extra = _android_guide()
        if p['key'] == 'ios':
            extra = _notice('warn', '以上应用均未在中国大陆区 App Store 上架，需使用其他地区（如美区）Apple ID 购买 / 下载。')
            extra = f'<div class="client-app">{extra}</div>'
        sections.append(
            f'<section class="panel" id="p-{p["key"]}"><div class="panel-head"><h2>'
            f'{_icon(_PLATFORM_ICON.get(p["key"], "monitor"), 16)}{_esc(p["label"])}</h2>{note}</div>'
            + lead + ''.join(_client_app(a) for a in p['apps']) + extra + '</section>')
    action = f'<a class="btn" href="/dashboard">{_icon("user", 15)}去用户中心导入</a>'
    body = f"""
  {_page_head('客户端下载', eyebrow='下载', eyebrow_icon='download',
              lede='按平台挑一个客户端安装，再到用户中心「一键导入」订阅。桌面端推荐 Clash Verge Rev，Android 推荐 FlClash，iOS 推荐 Shadowrocket。',
              actions=action)}
  {status}
  <div class="chip-row" style="margin:0 0 16px">{nav}</div>
  {''.join(sections)}
  <section class="panel"><div class="panel-head"><h2>{_icon('zap', 16)}装好之后</h2></div>
    <div class="panel-body"><ol class="flow" style="margin-top:0">
      <li><strong>登录用户中心</strong><span class="muted">在「订阅控制台 · 一键导入」点你的客户端，订阅自动写入。</span></li>
      <li><strong>不支持一键导入？</strong><span class="muted">复制「订阅链接」粘贴到客户端的订阅 / 配置 URL；v2rayN / v2rayNG 在链接末尾加 <code>?fmt=uri</code>（链接已含 <code>?</code> 时用 <code>&amp;fmt=uri</code>）。</span></li>
      <li><strong>开启代理</strong><span class="muted">选「自动选择」或按地区挑节点；客户端会按周期自动更新订阅。</span></li>
    </ol></div>
  </section>"""
    return _shell(f'{VISIBLE_BRAND} · 客户端下载', body,
                  app=True, active='clients', role=role,
                  logout_csrf=str(logout_csrf or ''))


def docs_page(role: str = 'user', logout_csrf: str = '') -> str:
    toc = ''.join(f'<a href="#doc-{key}">{_esc(title)}</a>' for key, title, _ in _DOC_SECTIONS)
    panels = ''.join(
        f'<section class="panel" id="doc-{key}"><div class="panel-head"><h2>{_esc(title)}</h2></div>'
        + ''.join(f'<div class="endpoint"><code>{_esc(ep)}</code><p>{_esc(desc)}</p></div>'
                  for ep, desc in items)
        + '</section>'
        for key, title, items in _DOC_SECTIONS)
    body = f"""
  {_page_head('技术文档', eyebrow='参考', eyebrow_icon='file-text',
              lede='订阅端点、格式适配、认证模型、对齐机制与运维工具的完整说明。',
              actions=f'<a class="btn" href="/dashboard">{_icon("user", 15)}返回我的面板</a>')}
  <div class="docs-layout">
    <nav class="toc" aria-label="文档目录"><p class="toc-title">目录</p>{toc}</nav>
    <div>{panels}</div>
  </div>"""
    return _shell(f'{VISIBLE_BRAND} · 技术文档', body,
                  app=True, active='docs', role=role,
                  logout_csrf=str(logout_csrf or ''))


def audit_page(entries: Iterable[Dict[str, Any]], q: str,
               logout_csrf: str = '') -> str:
    rows = []
    for e in entries:
        detail = {k: v for k, v in e.items()
                  if k not in ('at', 'actor', 'action', 'target', 'ip')}
        detail_text = _esc(json.dumps(detail, ensure_ascii=False)) if detail else ''
        rows.append(
            f'<tr><td class="tabular" style="white-space:nowrap">{_esc(_fmt_ts(int(e.get("at") or 0)))}</td>'
            f'<td>{_esc(e.get("actor", ""))}</td>'
            f'<td><code>{_esc(e.get("action", ""))}</code></td>'
            f'<td>{_esc(e.get("target", ""))}</td>'
            f'<td class="mono">{_esc(e.get("ip", ""))}</td>'
            f'<td class="detail-cell">{detail_text}</td></tr>')
    tbody = ''.join(rows) or (
        f'<tr><td colspan="6"><div class="empty">{_icon("history", 30)}'
        f'<strong>暂无记录</strong><span>{"没有匹配的审计条目" if q else "还没有任何管理操作"}</span></div></td></tr>')
    body = f"""
  {_page_head('审计流水', eyebrow='管理', eyebrow_icon='shield',
              lede='管理员与账号安全操作记录（append-only），最近 500 条；不含任何口令或 token 明文。',
              actions=f'<a class="btn" href="/admin">{_icon("users", 15)}用户管理</a><a class="btn" href="/admin/audit/export">{_icon("download", 15)}导出 CSV</a>')}
  <section class="panel">
    <div class="panel-head">
      <form method="get" action="/admin/audit" class="toolbar" style="flex:1">
        <div class="input-icon">{_icon('search', 15)}<input type="search" name="q" value="{_esc(q)}" placeholder="按用户名/动作/IP 过滤" aria-label="过滤审计流水"></div>
        <button type="submit" class="btn">过滤</button>
      </form>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>对象</th><th>来源 IP</th><th>明细</th></tr></thead>
        <tbody>{tbody}</tbody>
      </table>
    </div>
  </section>"""
    return _shell(f'{VISIBLE_BRAND} · 审计', body,
                  app=True, active='audit', role='admin',
                  logout_csrf=str(logout_csrf or ''))


def admin_page(users: Iterable[Dict[str, Any]], tokens_by_id: Dict[str, Dict[str, Any]],
               csrf: str, *, msg: str = '', err: str = '', q: str = '',
               expiring: Optional[Iterable[Dict[str, Any]]] = None,
               near_quota: Optional[Iterable[Dict[str, Any]]] = None) -> str:
    users = list(users)
    expiring = list(expiring or [])
    near_quota = list(near_quota or [])
    banner = ''
    if expiring:
        names = '、'.join(_esc(u['username']) for u in expiring)
        banner += _notice('warn', f'<b>7 天内到期</b>：{names}（续期请用「设到期」操作）', 'clock')
    if near_quota:
        names = '、'.join(_esc(u['username']) for u in near_quota)
        banner += _notice('warn', f'<b>流量已达 85%</b>：{names}（超额即停发订阅）', 'activity')
    banner += _flash(msg, err)
    active_n = sum(1 for u in users if u.get('status') != 'disabled')
    rows = ''.join(_user_row(u, tokens_by_id.get(str(u.get('token_id') or '')), csrf)
                   for u in users)
    if not rows:
        rows = (f'<tr><td colspan="6"><div class="empty">{_icon("users", 30)}'
                f'<strong>{"没有匹配的用户" if q else "还没有用户"}</strong>'
                f'<span>{"换个关键词试试" if q else "在下方新建第一个用户"}</span></div></td></tr>')
    stats = ''.join([
        _stat('用户', _counter(len(users)), icon='users', note='当前列表' if q else '全部账号'),
        _stat('启用中', _counter(active_n), icon='check-circle'),
        _stat('7 天内到期', _counter(len(expiring)), icon='clock'),
        _stat('流量 ≥85%', _counter(len(near_quota)), icon='activity'),
    ])
    body = f"""
  {_page_head('用户与配额管理', eyebrow='管理', eyebrow_icon='shield',
              actions=f'<a class="btn" href="/admin/audit">{_icon("history", 15)}审计流水</a><a class="btn btn-primary" href="#new-user">{_icon("plus", 15)}新建用户</a>')}
  {banner}
  <div class="stats">{stats}</div>
  <section class="panel">
    <div class="panel-head">
      <form method="get" action="/admin" class="toolbar" style="flex:1">
        <div class="input-icon">{_icon('search', 15)}<input type="search" name="q" value="{_esc(q)}" placeholder="搜索用户名/邮箱/备注" aria-label="搜索用户"></div>
        <button type="submit" class="btn">搜索</button>
      </form>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>用户</th><th>状态</th><th>本期用量</th><th>到期</th><th>最后拉取</th><th>操作</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <details class="disclosure">
      <summary><span>配额与吊销说明</span>{_icon('chevron-down', 15)}</summary>
      <div class="disclosure-body"><p>用量仅统计自建节点上报字节；配额超限/到期/停用都会让订阅返回 401（客户端更新失败）。真踢人仍需节点侧轮换凭据（二期 per-user uuid）。审计流水见 <a href="/admin/audit">审计页</a>（可导出 CSV）。</p></div>
    </details>
  </section>
  <section class="panel" id="new-user">
    <div class="panel-head"><h2>{_icon('plus', 16)}新建用户</h2><span class="faint">创建后展示一次订阅链接</span></div>
    <div class="panel-body">
      <form method="post" action="/admin/users">
        <input type="hidden" name="csrf" value="{_esc(csrf)}">
        <div class="form-grid">
          <div class="field"><label class="label" for="n-user">用户名</label>
            <input type="text" id="n-user" name="username" required pattern="[a-z0-9][a-z0-9_-]{{2,31}}" autocapitalize="none" spellcheck="false">
            <span class="hint">小写字母/数字/_-，3–32 位</span></div>
          <div class="field"><label class="label" for="n-pass">初始密码</label>
            <input type="password" id="n-pass" name="password" required minlength="8" autocomplete="new-password">
            <span class="hint">至少 8 位</span></div>
          <div class="field"><label class="label" for="n-email">提醒邮箱（可空）</label>
            <input type="text" id="n-email" name="email" placeholder="user@example.com" inputmode="email"></div>
          <div class="field"><label class="label" for="n-notes">备注</label>
            <input type="text" id="n-notes" name="notes"></div>
          <div class="field"><label class="label" for="n-quota">月配额 GB</label>
            <input type="number" id="n-quota" name="quota_gb" value="100" min="0" step="1">
            <span class="hint">0 为不限</span></div>
          <div class="field"><label class="label" for="n-expire">有效期天数</label>
            <input type="number" id="n-expire" name="expire_days" value="0" min="0" step="1">
            <span class="hint">0 为不限</span></div>
          <div class="field"><label class="label" for="n-reset">重置日</label>
            <input type="number" id="n-reset" name="reset_day" value="1" min="1" max="28">
            <span class="hint">每月 1–28 日</span></div>
        </div>
        <div class="form-actions"><button type="submit" class="btn btn-primary">{_icon('plus', 15)}创建用户</button></div>
      </form>
    </div>
  </section>"""
    return _shell(f'{VISIBLE_BRAND} · 管理', body,
                  app=True, active='admin', role='admin', logout_csrf=csrf)
