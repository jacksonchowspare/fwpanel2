#!/usr/bin/env node
/*
 * 登录失效（401）处理回归（v3.3.24）
 *
 * 背景（用户实测，报障「配置 Docker 存储目录点了没反应、面板像卡死」时按 F12 给出的证据）：
 *   控制台是一整片 401 —— /api/status、/api/rules、/api/ssh、/api/docker、/api/procs… 全 401，
 *   外加 `Uncaught (in promise) Error: 未登录或登录已过期  at async renderSvc / renderRules`。
 *   原因：面板升级/重启会清空内存里的登录态，老页面的 token 就死了。而旧前端：
 *     ① 每收到一个 401 就再调一次 showLogin()，但**从不告诉用户原因**；
 *     ② 一次 refreshAll 会并发打十几个接口 → 十几个 401，界面像「点什么都没反应」；
 *     ③ renderSvc / renderRules 直接 await api() 没有 try/catch → 未捕获 Promise 异常，后续渲染整段中断。
 *
 * 断言：① 首个 401 只提示一次 + 只切一次登录页；② 之后普通请求直接短路（不再发网络请求）；
 *      ③ /api/login 永不被短路（否则没法重新登录）；④ 登录成功复位后恢复正常请求；
 *      ⑤ 非 401 错误不触发登录页；⑥ renderSvc/renderRules 失败时安静返回、不抛未捕获异常。
 *
 * 用法：node frontend_auth_401_test.js [index.html]
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

const apiSrc = extractFn("api");
if (!apiSrc) { console.log("提取 api 失败"); process.exit(2); }

function mkSandbox(status, opts) {
  opts = opts || {};
  const st = { fetches: [], showLogin: 0, toasts: [] };
  const sb = {
    console, JSON, Promise, Error, Math, Object, String, Number,
    setTimeout: (fn) => { if (fn) fn(); return 1; }, clearTimeout: () => {},
    AbortController: class { constructor() { this.signal = null; } abort() {} },
    fetch: async (url) => {
      st.fetches.push(url);
      return { ok: status === 200, status, json: async () => (opts.body || { error: "未登录或登录已过期" }) };
    },
    token: "TOK", API: "",
    localStorage: { _d: { fw_token: "TOK" }, getItem(k) { return this._d[k] || null; },
                    setItem(k, v) { this._d[k] = v; }, removeItem(k) { delete this._d[k]; } },
    showLogin: () => { st.showLogin++; },
    toast: (m, k) => { st.toasts.push({ m, k }); },
  };
  const ctx = vm.createContext(sb);
  // 声明 authLost（源文件里是模块级 let，不在 api 函数体内）
  vm.runInContext("let authLost = false;", ctx);
  vm.runInContext(apiSrc, ctx);
  return { ctx, st };
}

(async () => {
  console.log("== 1) 首个 401：提示一次 + 切登录页一次 + 抛错 ==");
  {
    const { ctx, st } = mkSandbox(401);
    let err = null;
    try { await vm.runInContext("api('GET','/api/status')", ctx); } catch (e) { err = e; }
    check(!!err, "抛错（调用方能感知失败）");
    check(st.showLogin === 1, "showLogin 只调用一次", "次数=" + st.showLogin);
    check(st.toasts.length === 1 && /登录已失效/.test(st.toasts[0].m), "给出可理解的原因（不只是切页面）", JSON.stringify(st.toasts));
    check(st.fetches.length === 1, "只发了一次网络请求");
    check(vm.runInContext("localStorage.getItem('fw_token')", ctx) === null, "顺手清掉失效 token（避免刷新页面再打一轮 401）");
    check(vm.runInContext("token", ctx) === "", "内存里的 token 也清空");
  }

  console.log("== 2) 后续请求直接短路（不再白发一堆 401）==");
  {
    const { ctx, st } = mkSandbox(401);
    try { await vm.runInContext("api('GET','/api/status')", ctx); } catch (e) {}
    for (const p of ["/api/rules", "/api/ssh", "/api/docker", "/api/procs"]) {
      try { await vm.runInContext("api('GET','" + p + "')", ctx); } catch (e) {}
    }
    check(st.fetches.length === 1, "5 次调用只发了 1 个请求（其余短路）", "请求数=" + st.fetches.length);
    check(st.showLogin === 1, "登录页也只切一次", "次数=" + st.showLogin);
  }

  console.log("== 3) /api/login 永不被短路 ==");
  {
    const { ctx, st } = mkSandbox(200, { body: { token: "NEW" } });
    vm.runInContext("authLost = true;", ctx);
    const d = await vm.runInContext("api('POST','/api/login',{username:'a',password:'b'})", ctx);
    check(d && d.token === "NEW", "登录接口照常请求并返回", JSON.stringify(d));
    check(st.fetches.length === 1, "确实发出了请求", "请求数=" + st.fetches.length);
  }

  console.log("== 4) 登录成功后复位 authLost，请求恢复正常 ==");
  {
    const { ctx, st } = mkSandbox(200, { body: { ok: true } });
    vm.runInContext("authLost = true;", ctx);
    vm.runInContext("authLost = false;", ctx);   // 模拟 login() 成功后的复位
    const d = await vm.runInContext("api('GET','/api/status')", ctx);
    check(d && d.ok === true, "复位后能正常拿到数据", JSON.stringify(d));
    check(st.fetches.length === 1, "确实发出了请求");
  }

  console.log("== 5) 非 401 错误不触发登录页 ==");
  {
    const { ctx, st } = mkSandbox(500, { body: { error: "服务器内部错误" } });
    let err = null;
    try { await vm.runInContext("api('GET','/api/status')", ctx); } catch (e) { err = e; }
    check(err && /服务器内部错误/.test(err.message), "原错误信息透传", err && err.message);
    check(st.showLogin === 0 && st.toasts.length === 0, "不切登录页、不弹登录失效提示");
  }

  console.log("== 6) renderSvc / renderRules 失败时安静返回（不产生未捕获异常）==");
  for (const fn of ["renderSvc", "renderRules"]) {
    const src = extractFn(fn);
    if (!src) { check(false, fn + " 提取失败"); continue; }
    const sb = { console, Promise, Error, JSON, API: "",
                 api: async () => { throw new Error("未登录或登录已过期"); } };
    const ctx = vm.createContext(sb);
    vm.runInContext(src, ctx);
    let rejected = false;
    try { await vm.runInContext(fn + "()", ctx); } catch (e) { rejected = true; }
    check(!rejected, fn + " 不抛未捕获异常（旧实现会在控制台报 Uncaught (in promise)）");
  }

  console.log("\n结果: " + pass + " 通过, " + fail + " 失败");
  process.exit(fail ? 1 : 0);
})();
