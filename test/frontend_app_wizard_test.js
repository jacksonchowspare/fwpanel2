#!/usr/bin/env node
/*
 * 应用向导流程回归（v3.3.1）
 *
 * 背景（用户真机实测三个症状，同源）：
 *   ① 模板随便选哪个，装出来都是 WordPress
 *   ② 「上一步」点了等于「下一步」（在步骤 1 点它直接开始部署）
 *   ③ 关掉向导再打开，随便点一下就按残留状态开始部署
 * 根因：模板单选框的 onchange 被 qjs 的双引号截断（处理器变成 appwPick( → 语法错误，永不生效）；
 *       appwStep(d) 完全不看 d；成功/失败时用 setAttribute 就地改写「下一步」的 onclick 且从不还原。
 *
 * 本测试直接驱动向导函数（mini 元素替身 + 记录 api 调用），断言：
 *   1) 选模板真的改状态，且部署请求带的是选中的模板
 *   2) 「上一步」只回退，绝不触发部署
 *   3) 失败后按钮变「重试」，但行为仍是规范入口 appwStep(1)（不是 appDeploy()）
 *   4) 关掉再打开，按钮文案与行为回到初始态（不再带着上次的副作用）
 *   5) 模板单选框的行内处理器可编译（引号没被截断）
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

/* ---- mini 元素替身（只需向导用到的这几种能力） ---- */
function makeEl(id) {
  const el = {
    id, innerHTML: "", textContent: "", value: "", checked: false, disabled: false,
    style: {}, attrs: {}, children: [],
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return this.attrs[k]; },
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    querySelector() { return makeEl(id + "_q"); },
    querySelectorAll() { return []; },
    appendChild(c) { this.children.push(c); },
    remove() {},
    addEventListener() {},
  };
  return el;
}

const els = {};
function $(id) {
  if (!els[id]) els[id] = makeEl(id);
  return els[id];
}

const calls = [];
let failNextDeploy = false;

const extract = ["esc", "qjs", "attrEsc", "btnHtml", "appwTpl", "appwDots", "appwRender", "appwStep",
                 "appDeploy", "openAppWizard", "closeAppWizard", "appwPick", "appwPortCheck",
                 "appwDomainTyped", "appwExposeTyped", "appwNextFreePort", "appwPortTyped", "appwShowLogs"];
const chunks = [], missing = [];
for (const n of extract) {
  const src = extractFn(n);
  if (src) chunks.push(src); else missing.push(n);
}

const sandbox = {
  $,
  __els: els,
  console,
  appTpls: [
    { id: "wordpress", name: "WordPress", icon: "📝", desc: "博客建站", default_port: 8080, upload_mb: 32, min_mem_mb: 900, images: { main: "wordpress:latest", db: "mariadb:11" }, notes: ["x"] },
    { id: "nextcloud", name: "Nextcloud", icon: "☁", desc: "网盘", default_port: 8081, upload_mb: 512, min_mem_mb: 1024, images: { main: "nextcloud:latest", db: "mariadb:11" } },
    { id: "vaultwarden", name: "Vaultwarden", icon: "🔐", desc: "密码库", default_port: 8082, upload_mb: 32, min_mem_mb: 512, images: { main: "vaultwarden/server:latest" }, require_domain: true },
    { id: "typecho", name: "Typecho", icon: "📄", desc: "轻量博客", default_port: 8083, upload_mb: 32, min_mem_mb: 512, images: { main: "typecho:latest", db: "mariadb:11" } },
  ],
  appMem: { total_mb: 2048 },
  siteRoot: "/var/www",
  appw: { failed: false, step: 0, tpl: "", port: null, domain: "", expose: false, name: "", upload: 32, imgMain: "", imgDb: "", task: "", result: null, checking: false },
  api: async (m, p, body) => {
    calls.push({ m, p, body });
    if (p === "/api/apps/port-check") return { ok: true, next_free: 9000 };
    if (p === "/api/tasks/x") return { status: "running", msg: "部署中" };
    if (p === "/api/apps") {
      if (failNextDeploy) { failNextDeploy = false; throw new Error("模拟部署失败"); }
      return { task: null, app: { id: "cccccccccccc", url: "http://x/" } };
    }
    return {};
  },
  toast: () => {},
  confirmPanel: (m, fn) => fn && fn(),
  confirm: () => false,
  loadApps: () => {},
  appOpen: () => {},
  appLogs: () => {},
  setTimeout: () => 0,
  clearTimeout: () => {},
  document: { getElementById: $, querySelectorAll: () => [], createElement: () => makeEl("tmp") },
  RequestAnimationFrame: () => 0,
};
vm.createContext(sandbox);
vm.runInContext(chunks.join("\n"), sandbox);

console.log("检查文件:", file);
if (missing.length) console.log("未抽到的函数（跳过相关断言）:", missing.join(", "));

/* ---------- ① 打开向导：初始态 ---------- */
console.log("① 打开向导的初始态");
sandbox.openAppWizard();
check(sandbox.appw.step === 0, "停在第一步（模板选择）", "step=" + sandbox.appw.step);
check(sandbox.appw.tpl === "wordpress", "默认选中第一个模板", sandbox.appw.tpl);
const nx = $("appw_next");
check(nx.textContent === "下一步", "按钮文案是「下一步」", nx.textContent);
check(nx.getAttribute("onclick") === "appwStep(1)", "按钮行为是规范入口 appwStep(1)", nx.getAttribute("onclick"));
check($("appw_back").style.display === "none", "第一步不显示「上一步」");

/* ---------- ② 模板选择真的生效 + 行内处理器没被截断 ---------- */
console.log("② 模板选择");
sandbox.appwPick("nextcloud");
check(sandbox.appw.tpl === "nextcloud", "选中 Nextcloud 后状态跟着变", sandbox.appw.tpl);
check(sandbox.appw.port === 8081, "端口跟着换成该模板默认端口", String(sandbox.appw.port));
const bodyHtml = $("appw_body").innerHTML;
check(/onchange="appwPick\(&quot;nextcloud&quot;\)"/.test(bodyHtml) || /onchange="appwPick\(&#34;nextcloud&#34;\)"/.test(bodyHtml) || /onchange="appwPick\(&quot;/.test(bodyHtml),
      "单选框的行内处理器带转义（引号不会被截断）", (bodyHtml.match(/onchange="[^"]*"/) || [""])[0]);
const rawHandler = (bodyHtml.match(/onchange="([^"]*)"/) || [])[1] || "";
try {
  new Function(rawHandler.replace(/&quot;/g, '"').replace(/&#34;/g, '"'));
  check(true, "行内处理器可编译");
} catch (e) {
  check(false, "行内处理器可编译", e.message + "  ← 这就是「模板选不中」的根因");
}

/* ---------- ③ 上一步 = 只回退，绝不部署 ---------- */
console.log("③ 「上一步」只回退");
sandbox.appwStep(1);                       // 0 → 1
check(sandbox.appw.step === 1, "下一步进入配置步", "step=" + sandbox.appw.step);
check($("appw_back").style.display === "", "配置步显示「上一步」");
calls.length = 0;
sandbox.appwStep(-1);                      // 点「上一步」
check(sandbox.appw.step === 0, "回到第一步", "step=" + sandbox.appw.step);
check(calls.length === 0, "★ 上一步没有发起任何请求（更没开始部署）", JSON.stringify(calls.slice(0, 2)));

/* ---------- ④ 部署请求带的是选中的模板 ---------- */
console.log("④ 部署请求的模板");
sandbox.appwPick("typecho");
sandbox.appwStep(1);                       // → 配置步
$("aw_port").value = "8099";
$("aw_name").value = "我的站";
$("aw_domain").value = "";
$("aw_upload").value = "32";
calls.length = 0;
sandbox.appwStep(1);                       // 配置步 → 开始部署
const deploy = calls.find(c => c.p === "/api/apps");
check(!!deploy, "确实发起了部署请求");
check(deploy && deploy.body && deploy.body.template === "typecho",
      "★ 部署的是选中的模板（不是恒为 wordpress）", deploy && JSON.stringify(deploy.body));
waitSetup();

function waitSetup() {
  // ⑤ 失败路径 + 关闭重开（异步：等 appDeploy 的 await 走完）
  setTimeout(async () => {
    console.log("⑤ 失败后按钮 + 关掉重开");
    sandbox.appw.step = 1;
    sandbox.appw.failed = false;
    failNextDeploy = true;
    calls.length = 0;
    await sandbox.appwStep(1);             // 触发一次必然失败的部署
    await new Promise(r => setTimeout(r, 20));
    check(sandbox.appw.failed === true, "失败被标记（按钮应显示「重试」）", "failed=" + sandbox.appw.failed);
    check(nx.textContent === "重试", "按钮文案变成「重试」", nx.textContent);
    check(nx.getAttribute("onclick") === "appwStep(1)",
          "★ 按钮行为仍是规范入口（旧版这里被改写成 appDeploy()，重开后一点就部署）", nx.getAttribute("onclick"));

    sandbox.closeAppWizard();
    sandbox.openAppWizard();
    check(nx.getAttribute("onclick") === "appwStep(1)", "关掉再打开：按钮行为没有被上次副作用污染", nx.getAttribute("onclick"));
    check(nx.textContent === "下一步", "关掉再打开：文案回到「下一步」", nx.textContent);
    check(nx.disabled === false, "关掉再打开：按钮可用");
    calls.length = 0;
    sandbox.appwStep(1);                   // 重开后点「下一步」只能进配置步，不该部署
    check(sandbox.appw.step === 1, "重开后「下一步」只前进一步", "step=" + sandbox.appw.step);
    check(!calls.some(c => c.p === "/api/apps"),
          "★ 重开后点一下不会立刻开始部署", JSON.stringify(calls.slice(0, 2)));

    console.log((fail === 0 ? "\n全部通过 ✓" : "\n失败 " + fail + " 项 ✗") + "（" + pass + " 通过）");
    process.exit(fail === 0 ? 0 : 1);
  }, 10);
}
