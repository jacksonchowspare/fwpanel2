#!/usr/bin/env node
/* BBR 开关的状态驱动行为测试（v3.2.32）
 *
 * 背景（用户实测）：BBR 已经是开启状态，按钮却永远写着「一键开启 BBR」，
 * 点下去弹的却是「确认关闭 BBR？」——因为按钮文案写死在 HTML 里，
 * 状态只渲染在 #sys_bbr 那行文字上，两者不同步。
 *
 * 现在按钮文案/样式/可用性一律由 renderBbrUi() 依据 sysData.bbr 决定：
 *   开着 → 「一键关闭 BBR」+ 危险样式；关着 → 「一键开启 BBR」；
 *   内核不支持 → 禁用并给出提示。
 * 另外 loadBbr() 不得用残缺响应（如 {}）覆盖系统页的权威状态。
 *
 * 用法：node test/frontend_bbr_ui_test.js   （全通过退出码 0）
 */
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "..", "static", "index.html"), "utf8");

function extract(name) {
    const marker = "function " + name + "(";
    let start = html.indexOf(marker);
    if (start < 0) return null;
    if (html.slice(start - 6, start) === "async ") start -= 6;   // async function 别把 async 切掉
    let depth = 0, end = start;
    for (; end < html.length; end++) {
        const c = html[end];
        if (c === "{") depth++;
        else if (c === "}") { depth--; if (depth === 0) { end++; break; } }
    }
    return html.slice(start, end);
}

const srcBbr = extract("renderBbrUi");
const srcLoad = extract("loadBbr");
let failures = 0;
function check(cond, label, extra) {
    console.log((cond ? "  ✓ " : "  ✗ ") + label + (cond || extra === undefined ? "" : "   → " + extra));
    if (!cond) failures++;
}

if (!srcBbr) { console.log("FAIL 找不到 renderBbrUi()"); process.exit(1); }
if (!srcLoad) { console.log("FAIL 找不到 loadBbr()"); process.exit(1); }

/* ---------------- 假 DOM ---------------- */
function mkEl(id) {
    return { id, textContent: "", innerHTML: "", className: "", disabled: false, title: "" };
}
const els = { sys_bbr: mkEl("sys_bbr"), sys_bbr_btn: mkEl("sys_bbr_btn") };
global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? "" : s);

let sysData = {};
global.sysData = sysData;

/* 从 index.html 现场抽取的函数在全局作用域里执行，才能读到 sysData/$/esc */
const factory = new Function(srcBbr + "\n" + srcLoad + "\nreturn {renderBbrUi: renderBbrUi, loadBbr: loadBbr};");
const apiFns = factory();
const renderBbrUi = apiFns.renderBbrUi;
const loadBbr = apiFns.loadBbr;

function render(state) {
    sysData = global.sysData = { bbr: state };
    renderBbrUi();
    return { btn: els.sys_bbr_btn.textContent, cls: els.sys_bbr_btn.className,
             dis: els.sys_bbr_btn.disabled, tip: els.sys_bbr_btn.title,
             line: els.sys_bbr.innerHTML };
}

console.log("① 已开启 → 按钮显示「一键关闭 BBR」");
let r = render({ enabled: true, supported: true, kernel: "6.1.0", current_cc: "bbr" });
check(r.btn === "一键关闭 BBR", "按钮文案 = 一键关闭 BBR", r.btn);
check(/\bdanger\b/.test(r.cls), "按钮带危险样式（视觉上区分）", r.cls);
check(r.dis === false, "按钮可用");
check(/已开启/.test(r.line) && /bbr/.test(r.line), "状态行写「已开启」并显示当前算法");

console.log("② 未开启 → 按钮显示「一键开启 BBR」");
r = render({ enabled: false, supported: true, kernel: "6.1.0", current_cc: "cubic" });
check(r.btn === "一键开启 BBR", "按钮文案 = 一键开启 BBR", r.btn);
check(!/\bdanger\b/.test(r.cls), "按钮不带危险样式", r.cls);
check(/未开启/.test(r.line), "状态行写「未开启」");

console.log("③ 内核不支持 → 按钮禁用 + 提示原因");
r = render({ enabled: false, supported: false, kernel: "3.10.0" });
check(r.dis === true, "按钮被禁用");
check(/不支持/.test(r.tip), "悬浮提示说明原因", r.tip);
check(/内核不支持/.test(r.line), "状态行也标注内核不支持");

console.log("④ 按钮文案必须来自状态，不得在 HTML 里写死");
// 统计前先去掉注释，否则函数里的说明文字会被算成"写死的文案"
const htmlNoComment = html.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
const hard = (htmlNoComment.match(/一键(开启|关闭) BBR/g) || []).length;
const inRender = (srcBbr.replace(/\/\*[\s\S]*?\*\//g, "").match(/一键(开启|关闭) BBR/g) || []).length;
check(inRender >= 2, "renderBbrUi 内部同时给出两种文案（按状态二选一）", "命中 " + inRender + " 处");
check(hard === inRender + 1, "除 HTML 初始文案外没有第二份写死的状态文案", "全文件(去注释)" + hard + " 处 / 函数内 " + inRender + " 处");

console.log("⑤ loadBbr 不得用残缺/陈旧响应覆盖权威状态");
(async () => {
    // /api/bbr 返回 {}（残缺）时，已开启状态必须保持
    global.api = async () => ({});
    global.bbrInfo = null;
    sysData = global.sysData = { bbr: { enabled: true, supported: true, kernel: "6.1.0", current_cc: "bbr" } };
    await loadBbr();
    check(sysData.bbr.enabled === true, "残缺响应 {} 不会把「已开启」冲成「未开启」", JSON.stringify(sysData.bbr));
    check(els.sys_bbr_btn.textContent === "一键关闭 BBR", "渲染仍为「一键关闭 BBR」", els.sys_bbr_btn.textContent);

    // 完整响应要能正常更新
    global.api = async () => ({ enabled: false, supported: true, kernel: "6.1.0", current_cc: "cubic" });
    await loadBbr();
    check(sysData.bbr.enabled === false && els.sys_bbr_btn.textContent === "一键开启 BBR",
          "完整响应能正常更新状态与按钮", els.sys_bbr_btn.textContent);

    // 内核不支持时不得被 supported:true 之外的值擦掉
    sysData = global.sysData = { bbr: { enabled: false, supported: false, kernel: "3.10.0" } };
    global.api = async () => ({ enabled: false });
    await loadBbr();
    check(sysData.bbr.supported === false && els.sys_bbr_btn.disabled === true,
          "响应缺 supported 字段时不覆盖原值（仍禁用）", String(sysData.bbr.supported));

    console.log(failures === 0 ? "\n全部通过 ✓" : "\n失败 " + failures + " 项 ✗");
    process.exit(failures === 0 ? 0 : 1);
})();
