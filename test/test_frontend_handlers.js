#!/usr/bin/env node
/*
 * 前端行内事件处理器回归（v3.0.2 新增）
 *
 * 背景：按钮用字符串拼 onclick="' + code + '" 时，若 code 里含双引号（JSON.stringify/qjs 的产物），
 * HTML 解析器会在第一个内层双引号处把属性截断 —— 例如
 *     onclick="window.open("https://x/",'_blank')"
 * 会被解析成 onclick="window.open(" 加一堆垃圾属性，点击时执行 `window.open(` → SyntaxError →
 * 按钮"完全没反应"（只有控制台有报错）。3.0.0/3.0.1 的网站卡片按钮、文件管理按钮全中此坑。
 *
 * 本测试按 HTML 规范分词标签属性并逐个校验：
 *   1) onclick/onchange 等行内属性必须能被 new Function() 编译（括号/引号完整）
 *   2) 不能出现"名字像 URL 或含括号"的属性（属性被截断后的典型症状）
 * 用法：node test/test_frontend_handlers.js [path/to/index.html]
 * 退出码非 0 = 有坏按钮。
 */
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const file = process.argv[2] || path.join(__dirname, "..", "static", "index.html");
const html = fs.readFileSync(file, "utf8");

// ---------- 1. 取页面主脚本，抽出渲染函数 ----------
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

const needed = ["esc", "qjs", "attrEsc", "btnHtml", "siteCardHtml", "sfRenderCrumb", "sfRenderRows",
                "fmtBytes", "fmtSpeed", "fmtTime",
                // v3.3.1：应用向导与备份表格的渲染产物也要过这道闸门
                // （旧版只覆盖站点卡片/文件管理 → 应用向导的 onchange 引号截断与备份表格的下载链接都漏了过去）
                "appwRender", "appwDots", "appwTpl", "bkTable", "bkFmt"];
const chunks = [];
const missing = [];
for (const n of needed) {
  const src = extractFn(n);
  if (src) chunks.push(src); else missing.push(n);
}
// 允许缺失（旧版本没有 attrEsc/siteCardHtml），但要在报告里说明
const sandbox = {
  $: id => sandbox.__els[id] || (sandbox.__els[id] = {
    innerHTML: "", textContent: "", value: "", checked: false, disabled: false,
    style: {}, attrs: {}, classList: { add() {}, remove() {}, toggle() {} },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return this.attrs[k]; },
    querySelector: () => ({ innerHTML: "" }),
    querySelectorAll: () => [],
    appendChild() {}, remove() {}, addEventListener() {},
  }),
  __els: {},
  sfSite: { id: "abc123456789", domain: "demo.example.com", port: 8080 },
  sfPath: "",
  document: { getElementById: id => sandbox.$(id), querySelectorAll: () => [], createElement: () => sandbox.$("__tmp") },
  // v3.3.1：应用向导渲染需要的最小状态
  appTpls: [
    { id: "wordpress", name: "WordPress", icon: "📝", desc: "博客建站", default_port: 8080, upload_mb: 32, min_mem_mb: 900, images: { main: "wordpress:latest", db: "mariadb:11" }, notes: ["注意 A"] },
    { id: "nextcloud", name: "Nextcloud", icon: "☁", desc: "网盘", default_port: 8081, upload_mb: 512, min_mem_mb: 1024, images: { main: "nextcloud:latest", db: "mariadb:11" } },
    { id: "vaultwarden", name: "Vaultwarden", icon: "🔐", desc: "密码库", default_port: 8082, upload_mb: 32, min_mem_mb: 512, images: { main: "vaultwarden/server:latest" }, require_domain: true },
  ],
  appMem: { total_mb: 2048 },
  appw: { failed: false, step: 0, tpl: "wordpress", port: 8080, upload: 32, domain: "", name: "", expose: false, imgMain: "", imgDb: "", result: null },
  siteRoot: "/var/www",
  toast: () => {},
  // 备份表格：模块名映射要用到 bkInfo
  bkInfo: { modules: [{ id: "config", name: "面板配置与规则" }, { id: "nginx", name: "nginx 配置" }] },
};
sandbox.document.getElementById = id => sandbox.$(id);
vm.createContext(sandbox);
vm.runInContext(chunks.join("\n"), sandbox);

// ---------- 2. 用 HTML 规范的分词方式解析标签属性 ----------
// 返回 [{name, value}]，与浏览器一致：双引号值遇到下一个 " 就结束（这正是被截断的地方）
function parseAttrs(tagText) {
  const attrs = [];
  let i = tagText.indexOf(" ");
  while (i !== -1 && i < tagText.length) {
    while (i < tagText.length && /\s/.test(tagText[i])) i++;
    if (i >= tagText.length || tagText[i] === ">" || tagText[i] === "/") break;
    let j = i;
    while (j < tagText.length && !/[\s=/>]/.test(tagText[j])) j++;
    const name = tagText.slice(i, j);
    let value = "";
    let k = j;
    while (k < tagText.length && /\s/.test(tagText[k])) k++;
    if (tagText[k] === "=") {
      k++;
      while (k < tagText.length && /\s/.test(tagText[k])) k++;
      const q = tagText[k];
      if (q === '"' || q === "'") {
        const end = tagText.indexOf(q, k + 1);
        value = tagText.slice(k + 1, end === -1 ? tagText.length : end);
        k = end === -1 ? tagText.length : end + 1;
      } else {
        let e = k;
        while (e < tagText.length && !/[\s>]/.test(tagText[e])) e++;
        value = tagText.slice(k, e); k = e;
      }
    }
    attrs.push({ name, value });
    i = k;
  }
  return attrs;
}

// HTML 实体还原（属性值里的 &quot; 会被浏览器还原成 "）
function decode(s) {
  return s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<")
          .replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

const problems = [];
const seen = [];
function checkHtml(label, frag) {
  for (const tag of frag.match(/<[a-zA-Z][^>]*>/g) || []) {
    const attrs = parseAttrs(tag);
    for (const a of attrs) {
      const isHandler = /^on[a-z]+$/i.test(a.name);
      const suspicious = /[:()]/.test(a.name) || a.name.length > 24;   // 被截断后的垃圾属性
      if (suspicious) problems.push(label + " → 标签属性被截断，出现垃圾属性名: '" + a.name + "'  (" + tag.slice(0, 90) + ")");
      if (!isHandler) continue;
      const code = decode(a.value);
      seen.push(a.name + " = " + code.slice(0, 60));
      try {
        new Function(code);
      } catch (e) {
        problems.push(label + " → " + a.name + " 无法编译（点击必然静默失败）: " + JSON.stringify(code.slice(0, 120)) + " — " + e.message);
      }
    }
  }
}

// ---------- 3. 用真实形态的数据渲染卡片 ----------
const sites = [
  { id: "904d5f3c84c1", source: "site", type: "static", domain: "fwtest.imaster.dpdns.org", enabled: true,
    root: "/var/www/fwtest.imaster.dpdns.org", url: "https://fwtest.imaster.dpdns.org/", cert_mode: "auto",
    cert: { on: true, ref: "fwtest.imaster.dpdns.org", days: 89 }, label: "静态站" },
  { id: "02a6057363a8", source: "site", type: "port", port: 18080, enabled: true, root: "/srv/port",
    url: "http://1.2.3.4:18080/", cert_mode: "none", cert: {}, label: "端口站" },
  { id: "p_7c3aac4cfac6", source: "proxy", type: "proxy", domain: "sg1panel.isusz.com", enabled: true,
    upstream: "http://127.0.0.1:42608", url: "https://sg1panel.isusz.com/", cert: { on: true, days: 70 }, label: "反代站" },
];
if (typeof sandbox.siteCardHtml === "function") {
  sites.forEach((s, i) => checkHtml("siteCardHtml[" + (s.domain || s.port) + "]", sandbox.siteCardHtml(s)));
} else {
  problems.push("未找到 siteCardHtml（无法验证站点卡片）");
}

if (typeof sandbox.sfRenderCrumb === "function") {
  sandbox.sfSite = sites[0];
  sandbox.sfRenderCrumb("assets/css/main.css");
  checkHtml("sfRenderCrumb", sandbox.__els["sf_crumb"] ? sandbox.__els["sf_crumb"].innerHTML : "");
}
if (typeof sandbox.sfRenderRows === "function") {
  sandbox.sfSite = sites[0];
  try {
    sandbox.sfRenderRows({ path: "", items: [
      { name: "css", dir: true, mode: "0755", mtime: 1757500000 },
      { name: "index.html", dir: false, editable: true, mode: "0644", mtime: 1757500000, size: 861 },
      { name: "site.zip", dir: false, mode: "0644", mtime: 1757500000, size: 2048 },
    ] });
    checkHtml("sfRenderRows", sandbox.__els["sf_rows"] ? sandbox.__els["sf_rows"].innerHTML : "");
  } catch (e) { problems.push("sfRenderRows 抛错: " + e.message); }
}

// ---------- 3b. 应用向导与备份表格（v3.3.1 纳入闸门） ----------
if (typeof sandbox.appwRender === "function") {
  try {
    sandbox.appw.step = 0;
    sandbox.appwRender();
    checkHtml("appwRender(step0 模板列表)", sandbox.__els["appw_body"] ? sandbox.__els["appw_body"].innerHTML : "");
    sandbox.appw.step = 4;
    sandbox.appwRender();
    checkHtml("appwRender(step4 完成页)", sandbox.__els["appw_body"] ? sandbox.__els["appw_body"].innerHTML : "");
  } catch (e) {
    problems.push("appwRender 抛错: " + e.message);
  }
} else {
  problems.push("未找到 appwRender（无法验证应用向导）");
}

if (typeof sandbox.bkTable === "function") {
  try {
    sandbox.$("bk_table");
    sandbox.bkTable([
      { name: "fwpanel-host-v3.3.0-20260917-210000.tar.gz", size: 24576, time: 1758100000,
        modules: ["config", "nginx"], hostname: "ak", panel_version: "3.3.0", note: "换机前", pre_restore: false },
      { name: "pre-restore-fwpanel-host-20260917-205900.tar.gz", size: 20480, time: 1758099000,
        modules: ["config"], hostname: "ak", panel_version: "3.3.0", note: "", pre_restore: true },
    ]);
    const tb = sandbox.__els["bk_table"] && sandbox.__els["bk_table"].querySelector("tbody");
    checkHtml("bkTable", tb && tb.innerHTML ? tb.innerHTML : "");
  } catch (e) {
    problems.push("bkTable 抛错: " + e.message);
  }
}

// ---------- 4. 结果 ----------
console.log("检查文件:", file);
console.log("行内处理器共", seen.length, "个");
(seen.slice(0, 8).forEach(s => console.log("   ", s)));
if (seen.length > 8) console.log("    ...(略)");
if (missing.length) console.log("未抽到的函数:", missing.join(", "));
if (problems.length) {
  console.log("\n❌ 发现", problems.length, "个问题：");
  problems.forEach(p => console.log("   -", p));
  process.exit(1);
}
console.log("\n✅ 全部行内处理器可编译、无属性截断");
