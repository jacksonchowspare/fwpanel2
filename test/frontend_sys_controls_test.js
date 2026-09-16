#!/usr/bin/env node
/* 系统页控件状态驱动测试（v3.2.33）
 *
 * 1) 时区可下拉选择：loadTimezones() 把后端列表填进 datalist，sysTimeSave() 保存前
 *    先按列表校验（避免手打错一个字母白跑一趟）
 * 2) IPv6 三个动作按钮：当前状态那个标「（当前）」并禁用，重复渲染不叠加
 * 3) NTP 按状态只显示该做的那个按钮，状态未知时两个都留着
 *
 * 用法：node test/frontend_sys_controls_test.js   （全通过退出码 0）
 */
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "..", "static", "index.html"), "utf8");

function extract(name) {
    const marker = "function " + name + "(";
    let start = html.indexOf(marker);
    if (start < 0) return null;
    if (html.slice(start - 6, start) === "async ") start -= 6;
    let depth = 0, end = start;
    for (; end < html.length; end++) {
        const c = html[end];
        if (c === "{") depth++;
        else if (c === "}") { depth--; if (depth === 0) { end++; break; } }
    }
    return html.slice(start, end);
}

let failures = 0;
function check(cond, label, extra) {
    console.log((cond ? "  ✓ " : "  ✗ ") + label + (cond || extra === undefined ? "" : "   → " + extra));
    if (!cond) failures++;
}

const names = ["renderIpv6Ui", "renderSysTime", "loadTimezones", "sysTimeSave"];
const srcs = names.map(extract);
names.forEach((n, i) => { if (!srcs[i]) { console.log("FAIL 找不到 " + n + "()"); process.exit(1); } });

/* ---------------- 假 DOM / 假环境 ---------------- */
function mkEl(id) {
    return { id, textContent: "", innerHTML: "", className: "", disabled: false, title: "",
             value: "", style: { display: "" } };
}
const els = {};
function need(id) { return els[id] || (els[id] = mkEl(id)); }
["sys_ipv6", "sys_v6_enable", "sys_v6_disable", "sys_v6_v4first",
 "sys_tz", "sys_tz_list", "sys_time", "btn_ntp_on", "btn_ntp_off"].forEach(need);
need("sys_v6_enable").textContent = "开启 IPv6";
need("sys_v6_disable").textContent = "禁用 IPv6";
need("sys_v6_v4first").textContent = "IPv4 优先";
need("sys_tz").value = "";

global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? "" : s);
const toasts = [];
global.toast = (m, k) => toasts.push([String(m), k || ""]);
let posted = [];
global.sysRun = (p, b) => posted.push([p, b]);
let apiResult = null, apiCalls = [];
global.api = async (m, p) => { apiCalls.push(m + " " + p); if (apiResult instanceof Error) throw apiResult; return apiResult; };

/* 抽出来的函数依赖脚本里的模块级变量，这里补上 */
const PRELUDE = "let tzList = [], tzLoading = false;\n";
const factory = new Function(PRELUDE + srcs.join("\n") + "\nreturn {renderIpv6Ui: renderIpv6Ui, renderSysTime: renderSysTime, loadTimezones: loadTimezones, sysTimeSave: sysTimeSave};");
const F = factory();

console.log("① 时区下拉：列表来自后端，常用的排最前");
apiResult = { zones: ["Asia/Shanghai", "Asia/Tokyo", "Europe/London", "America/New_York"], current: "Asia/Shanghai" };
(async () => {
    await F.loadTimezones();
    const dl = els.sys_tz_list.innerHTML;
    check(/Asia\/Shanghai/.test(dl) && /America\/New_York/.test(dl), "datalist 已填入后端时区");
    check(dl.indexOf("Asia/Shanghai") < dl.indexOf("Asia/Tokyo"), "顺序沿用后端（常用在前）");
    check(dl.split("<option").length - 1 === 4, "选项数量正确", String(dl.split("<option").length - 1));
    const before = apiCalls.length;
    await F.loadTimezones();
    check(apiCalls.length === before, "第二次调用不再重复请求（只拉一次）");

    console.log("② 时区保存：先按列表校验");
    posted = []; toasts.length = 0;
    els.sys_tz.value = "Asia/Shangai";     // 故意打错一个字母
    await F.sysTimeSave();
    check(posted.length === 0, "打错时区不发请求（本地就拦下）", JSON.stringify(posted));
    check(/没有这个时区/.test(toasts[0] ? toasts[0][0] : ""), "给出明确提示", JSON.stringify(toasts));
    els.sys_tz.value = "Asia/Tokyo";
    await F.sysTimeSave();
    check(posted.length === 1 && posted[0][0] === "/api/system/time" && posted[0][1].tz === "Asia/Tokyo",
          "合法时区正常提交", JSON.stringify(posted));
    els.sys_tz.value = "   ";
    await F.sysTimeSave();
    check(posted.length === 1 && /请选择或输入时区/.test(toasts[toasts.length - 1][0]), "空值给出提示且不提交");

    console.log("③ 列表拉不到时不挡人（仍可手输）");
    global.api = async () => { throw new Error("network"); };
    const f2 = new Function(PRELUDE + srcs.join("\n") + "\nreturn {loadTimezones: loadTimezones, sysTimeSave: sysTimeSave};")();
    await f2.loadTimezones();
    posted = []; toasts.length = 0;
    els.sys_tz.value = "Asia/Kathmandu";
    await f2.sysTimeSave();
    check(posted.length === 1 && posted[0][1].tz === "Asia/Kathmandu", "无列表时不做本地拦截，直接提交", JSON.stringify(posted));

    console.log("④ IPv6：当前状态那个按钮标「（当前）」并禁用");
    F.renderIpv6Ui("enabled");
    check(els.sys_v6_enable.disabled === true && /（当前）/.test(els.sys_v6_enable.textContent), "已开启 → 「开启 IPv6（当前）」禁用");
    check(els.sys_v6_disable.disabled === false && els.sys_v6_disable.textContent === "禁用 IPv6", "其它按钮可用且文案干净");
    F.renderIpv6Ui("enabled");   // 重复渲染不得叠加
    check(els.sys_v6_enable.textContent === "开启 IPv6（当前）", "重复渲染不叠加「（当前）」", els.sys_v6_enable.textContent);
    F.renderIpv6Ui("v4_first");
    check(els.sys_v6_v4first.disabled === true && els.sys_v6_enable.disabled === false, "切到 v4_first 后高亮跟着变");
    F.renderIpv6Ui("disabled");
    check(els.sys_v6_disable.disabled === true && /已禁用/.test(els.sys_ipv6.innerHTML), "禁用状态：文案与按钮一致");
    F.renderIpv6Ui("weird");
    check(/未知/.test(els.sys_ipv6.innerHTML), "未知状态不硬猜，提示刷新");

    console.log("⑤ NTP：按状态只显示该做的那个");
    F.renderSysTime({ time: { timezone: "Asia/Shanghai", time: "2026-09-16 23:00:00", ntp: true } });
    check(els.btn_ntp_off.style.display === "inline-block" && els.btn_ntp_on.style.display === "none", "NTP 已开 → 只给「关闭 NTP」");
    check(/已开启/.test(els.sys_time.innerHTML), "状态行显示已开启");
    F.renderSysTime({ time: { timezone: "Asia/Shanghai", time: "x", ntp: false } });
    check(els.btn_ntp_on.style.display === "inline-block" && els.btn_ntp_off.style.display === "none", "NTP 已关 → 只给「开启 NTP」");
    F.renderSysTime({ time: { timezone: "Asia/Shanghai", time: "x", ntp: null } });
    check(els.btn_ntp_on.style.display === "inline-block" && els.btn_ntp_off.style.display === "inline-block",
          "状态未知 → 两个按钮都留着（不给用户死路）");

    console.log(failures === 0 ? "\n全部通过 ✓" : "\n失败 " + failures + " 项 ✗");
    process.exit(failures === 0 ? 0 : 1);
})();
