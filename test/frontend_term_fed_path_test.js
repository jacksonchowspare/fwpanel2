#!/usr/bin/env node
/*
 * Web 终端在「节点态」下的后端路径回归（v3.3.21）
 *
 * 背景（真机 UI 实测发现）：
 *   enterFed(n) 会把全局 API 设为 "/api/fed/<id>"，而 api() 内部就是 fetch(API + path)。
 *   终端代码却另外用 termApiPrefix(fedId) 又拼了一次 /api/fed/<id> —— 于是节点态下变成
 *     POST /api/fed/<id>/api/fed/<id>/api/term/key
 *   实测后果：① 远程终端的 /api/term/info 探针静默失败（不再提示 term 用户缺失/并发已满）；
 *   ② 「密钥」注入在远程终端完全不可用，节点把双前缀路径当「仅本机」端点拒成 401，
 *      主控回 502「节点拒绝访问：联邦令牌可能已失效」——用户看到误导性提示，密钥没注入；
 *   ③ 关窗时的 DELETE /api/term/key 同理失败（远程路径下临时私钥可能残留）。
 *   WS 地址走 termWsUrl() 自己拼前缀（不经 api()），所以「终端能连上」掩盖了这个 bug。
 *
 * 本测试用真实 api() + 桩 fetch 驱动 termPickKey / termDelKey / openTerm，断言：
 *   1) 节点态下，/api/term/key 与 /api/term/info 的 URL 只含一个 /api/fed/<id>
 *   2) 本机态（API="")路径保持 /api/term/...（不回归）
 *   3) 密钥上传成功时会 paste 出 ssh -i <临时路径>（功能闭环）
 * 用法：node frontend_term_fed_path_test.js [index.html]   （传修复前的文件应全红）
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const file = process.argv[2] || path.join(__dirname, "..", "static", "index.html");
const html = fs.readFileSync(file, "utf8");
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const js = scripts.sort((a, b) => b.length - a.length)[0];

function extractFn(name) {
  const re = new RegExp("(?:async\\s+)?function\\s+" + name + "\\s*\\(");
  const m = re.exec(js);
  if (!m) return null;
  let depth = 0, started = false;
  for (let j = m.index; j < js.length; j++) {
    if (js[j] === "{") { depth++; started = true; }
    else if (js[j] === "}") { depth--; if (started && depth === 0) return js.slice(m.index, j + 1); }
  }
  return null;
}

let pass = 0, fail = 0;
function check(cond, label, extra) {
  if (cond) { pass++; console.log("  ✓ " + label); }
  else { fail++; console.log("  ✗ " + label + (extra ? "  → " + extra : "")); }
}

const want = ["api", "termPickKey", "termDelKey", "termWsUrl", "openTerm", "termCtxAction"];
const chunks = [], missing = [];
for (const n of want) { const s = extractFn(n); if (s) chunks.push(s); else missing.push(n); }
if (missing.length) { console.log("提取失败: " + missing.join(",")); process.exit(2); }
// 修复前的版本里有 termApiPrefix()（会让节点态重复拼前缀）—— 存在就一并提取，
// 这样用修复前的 index.html 跑本测试时，红的是「前缀重复」本身，而不是「函数缺失」。
for (const n of ["termApiPrefix"]) { const s2 = extractFn(n); if (s2) chunks.push(s2); }

const fetched = [];
const toasts = [];
const NODE_ID = "1d744c9e7106";
let API = "";
let token = "TESTTOKEN";

function makeWin() {
  return {
    fedId: NODE_ID, keyPath: null, fontSize: 13, min: false, maxed: false,
    host: { addEventListener() {}, getBoundingClientRect: () => ({ left: 0, top: 0, width: 800, height: 500 }) },
    fileEl: { files: [{ size: 512, name: "id_test", text: async () => "-----BEGIN OPENSSH PRIVATE KEY-----\nxxxx\n-----END OPENSSH PRIVATE KEY-----\n" }], value: "" },
    keysName: { textContent: "" },
    keysRow: { classList: { contains: () => false, toggle() {}, add() {} } },
    term: { paste(t) { this.pasted = (this.pasted || "") + t; }, writeln() {}, focus() {}, onData() {}, loadAddon() {}, open() {}, options: {}, dispose() {} },
    fit: { fit() {} }, el: { querySelectorAll: () => [], querySelector: () => null, appendChild() {} },
    ctxEl: null, ws: null,
  };
}

const sandbox = {
  console, setTimeout, clearTimeout, Promise, JSON, Math, Date, encodeURIComponent,
  toast: (m, k) => toasts.push({ m, k }),
  TERM_WINS: [], TERM_MAX_WIN: 8, TERM_SEQ: 0,
  termNewSeq: () => ++sandbox.TERM_SEQ,
  termMakeWin: () => { const w = makeWin(); sandbox.TERM_WINS.push(w); return w; },
  termPalette: () => ({ theme: {} }), termThemeDefault: () => "dark", termFontBase: () => 13,
  termBindFontKeys() {}, termApplyFit() {}, termMakeDock() {}, termCtxMake() {}, termNote() {},
  termSetDot() {}, termSendResize() {}, termFit() {}, termWriteBanner() {}, termApplyTheme() {},
  termKeyRowBind() {}, termCtxBind() {}, termResizeBind() {}, termMin() {}, termRestore() {},
  fitAddonCtor: null,
  fedNode: null, location: { protocol: "https:", host: "akpanel.isusz.com" },
  fetch: async (url) => { fetched.push(url); return { ok: true, status: 200, json: async () => ({ available: true, busy: 0, max: 4, path: "/home/term/.ssh/fwterm_test.pem" }), text: async () => "" }; },
  AbortController: class { constructor() { this.signal = {}; } abort() {} },
  FileReader: class {}, WebSocket: class { constructor() { this.readyState = 1; } send() {} close() {} },
  // xterm 桩：构造函数返回一个「任何方法都可调用」的 Proxy 实例（openTerm 用到 onData/onResize/getSelection 等一串）
  Terminal: function (o) {
    const inst = { options: o || {}, pasted: "" };
    return new Proxy(inst, { get: (t, k) => (k in t) ? t[k] : (k === "getSelection" ? () => "" : () => {}) });
  },
};
sandbox.FitAddon = { FitAddon: class { fit() {} } };
sandbox.window = sandbox; sandbox.globalThis = sandbox;

const ctx = vm.createContext(sandbox);
// api() 会读模块级 authLost（v3.3.24 登录失效短路），沙箱里要先声明，否则调用时 ReferenceError
vm.runInContext("let authLost = false;\n" + chunks.join("\n"), ctx);
// 让沙箱里的 api() 用本测试的 API/token 变量（它们是全局 let，需显式赋值）
vm.runInContext("var __set = (a, t) => { API = a; token = t; };", ctx);

function setMode(nodeMode) {
  fetched.length = 0; toasts.length = 0;
  vm.runInContext(`__set(${nodeMode ? JSON.stringify("/api/fed/" + NODE_ID) : '""'}, "TESTTOKEN");`, ctx);
}
const countFed = (u) => (u.match(/\/api\/fed\//g) || []).length;

(async () => {
  console.log("== 1) 节点态：密钥上传路径只能有一个 /api/fed/<id> ==");
  setMode(true);
  const w1 = makeWin();
  await vm.runInContext("termPickKey(__W)", Object.assign(ctx, { __W: w1 }));
  const up = fetched.find(u => u.includes("/api/term/key")) || "";
  check(countFed(up) === 1, "POST /api/term/key 前缀不重复", up);
  check(up === "/api/fed/" + NODE_ID + "/api/term/key", "URL 精确匹配", up);
  check(String(w1.term.pasted || "").includes("ssh -i "), "上传成功后 paste 出 ssh -i", String(w1.term.pasted || ""));
  check(toasts.some(t => String(t.m).includes("已临时注入")), "提示「私钥已临时注入」");

  console.log("== 2) 节点态：删密钥路径同样不能重复 ==");
  setMode(true);
  const w2 = makeWin(); w2.keyPath = "/home/term/.ssh/fwterm_x.pem";
  await vm.runInContext("termDelKey(__W)", Object.assign(ctx, { __W: w2 }));
  const del = fetched.find(u => u.includes("/api/term/key")) || "";
  check(countFed(del) === 1, "DELETE /api/term/key 前缀不重复", del);

  console.log("== 3) 节点态：开终端的可用性探针 ==");
  setMode(true);
  // openTerm 用全局 fedNode 决定 fedId（远程终端场景），必须设上才会走 /api/fed 路径
  vm.runInContext('fedNode = { id: "' + NODE_ID + '", name: "sg2-测试节点", url: "https://sg2panel.isusz.com" };', ctx);
  await vm.runInContext("openTerm()", ctx);
  const info = fetched.find(u => u.includes("/api/term/info")) || "";
  check(countFed(info) === 1, "/api/term/info 前缀不重复", info);
  check(info === "/api/fed/" + NODE_ID + "/api/term/info", "探针 URL 精确匹配", info);

  console.log("== 4) 本机态：路径不带前缀（不回归）==");
  setMode(false);
  vm.runInContext("fedNode = null;", ctx);
  const w4 = makeWin(); w4.fedId = null;
  await vm.runInContext("termPickKey(__W)", Object.assign(ctx, { __W: w4 }));
  const up2 = fetched.find(u => u.includes("/api/term/key")) || "";
  check(up2 === "/api/term/key", "本机态仍是 /api/term/key", up2);

  console.log("== 5) WS 地址（节点态仍带前缀，与 api() 分工不同）==");
  const ws = vm.runInContext(`termWsUrl(${JSON.stringify(NODE_ID)})`, ctx);
  check(countFed(ws) === 1 && ws.startsWith("wss://akpanel.isusz.com/api/fed/" + NODE_ID + "/api/term/ws?token="), "WS URL 一个前缀 + wss", ws);

  console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
  process.exit(fail ? 1 : 0);
})();
