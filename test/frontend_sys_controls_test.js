#!/usr/bin/env node
/* 系统页控件状态驱动测试（v3.2.33 起；时区部分 v3.2.34 改为自绘下拉）
 *
 * 1) 时区自绘下拉：点框就展开（**框里有内容时也要能展开** —— 原生 datalist 正是这里不弹，
 *    用户实测"打不开"）、输入即筛选、点条目即选中并收起、Esc/点别处收起、Enter 选第一个匹配
 * 2) sysTimeSave() 保存前按列表校验（打错一个字母当场提示，不白跑一趟请求）
 * 3) IPv6 三个动作按钮：当前状态那个标「（当前）」并禁用，重复渲染不叠加
 * 4) NTP 按状态只显示该做的那个按钮，状态未知时两个都留着
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

const names = ["renderIpv6Ui", "renderSysTime", "loadTimezones", "tzItemHtml", "tzRender",
               "tzOpen", "tzClose", "tzToggle", "tzInput", "tzKey", "sysTimeSave",
               "sysNtpSet", "sysNtpToggle"];
const srcs = names.map(extract);
names.forEach((n, i) => { if (!srcs[i]) { console.log("FAIL 找不到 " + n + "()"); process.exit(1); } });

/* ---------------- 假 DOM ---------------- */
function mkEl(id) {
    const el = { id, textContent: "", innerHTML: "", className: "", disabled: false, title: "",
                 value: "", style: { display: "" }, _h: {}, _inside: false };
    el.classList = (function () {
        const set = new Set();
        return { add: c => set.add(c), remove: c => set.delete(c), contains: c => set.has(c) };
    })();
    el.addEventListener = (ev, fn) => { (el._h[ev] = el._h[ev] || []).push(fn); };
    el.contains = (t) => t === el || (t && t._inside === true);
    return el;
}
const els = {};
const need = (id) => els[id] || (els[id] = mkEl(id));
["sys_ipv6", "sys_v6_enable", "sys_v6_disable", "sys_v6_v4first", "sys_tz", "tz_pop", "tz_list",
 "tz_wrap", "sys_time", "btn_ntp_on", "btn_ntp_off"].forEach(need);
need("sys_v6_enable").textContent = "开启 IPv6";
need("sys_v6_disable").textContent = "禁用 IPv6";
need("sys_v6_v4first").textContent = "IPv4 优先";

const docHandlers = [];
global.document = { addEventListener: (ev, fn) => docHandlers.push(fn) };
global.$ = (id) => els[id] || null;
global.esc = (s) => String(s == null ? "" : s);
const toasts = [];
global.toast = (m, k) => toasts.push([String(m), k || ""]);
let cfm = null;
global.confirmPanel = (msg, onOk, title) => { cfm = { msg: String(msg || ""), onOk: onOk, title: title || "" }; };
let loaded = 0;
global.loadSystem = () => { loaded++; };
let posted = [];
global.sysRun = (p, b) => posted.push([p, b]);
let apiResult = null, apiCalls = [];
global.api = async (m, p) => { apiCalls.push(m + " " + p); if (apiResult instanceof Error) throw apiResult; return apiResult; };

/* 抽出来的函数依赖脚本里的模块级变量，这里补上 */
const PRELUDE = "let tzList = [], tzCommon = [], tzLoading = false, tzBound = false;\n";
const F = new Function(PRELUDE + srcs.join("\n") + "\nreturn {" +
    "renderIpv6Ui: renderIpv6Ui, renderSysTime: renderSysTime, loadTimezones: loadTimezones, tzRender: tzRender," +
    "tzOpen: tzOpen, tzClose: tzClose, tzToggle: tzToggle, tzInput: tzInput, tzKey: tzKey, " +
    "sysTimeSave: sysTimeSave, sysNtpSet: sysNtpSet, sysNtpToggle: sysNtpToggle};")();

function fireList(ev, target) {
    (els.tz_list._h[ev] || []).forEach(fn => fn({ target: target, preventDefault() {} }));
}
function itemEl(tz) {
    const it = { _tz: tz };
    it.getAttribute = () => tz;
    it.closest = (sel) => (sel === ".tz-item" ? it : null);
    return it;
}
function isOpen() { return els.tz_pop.classList.contains("show"); }

(async () => {
    console.log("① 时区下拉：列表填充与分组");
    apiResult = { zones: ["Asia/Shanghai", "UTC", "Asia/Tokyo", "America/New_York", "Asia/Kathmandu"],
                  common: ["Asia/Shanghai", "UTC"], current: "Asia/Shanghai" };
    els.sys_tz.value = "Asia/Shanghai";
    await F.loadTimezones();
    const full = els.tz_list.innerHTML;
    check(/tz-grp">常用/.test(full) && /tz-grp">全部时区（5）/.test(full), "渲染出「常用」与「全部时区（N）」两组", full.slice(0, 60));
    check((full.match(/class="tz-item/g) || []).length === 5, "条目数 = 列表数",
          String((full.match(/class="tz-item/g) || []).length));
    check(/class="tz-item on" data-tz="Asia\/Shanghai"/.test(full), "当前时区被标记高亮（on）");
    check(full.indexOf("常用") < full.indexOf("全部时区"), "常用组排在全部之前");
    const before = apiCalls.length;
    await F.loadTimezones();
    check(apiCalls.length === before, "第二次调用不再重复请求（只拉一次）");

    console.log("② 框里有内容时点框必须能展开，且展开的是完整列表（原生 datalist 的老毛病）");
    check(!isOpen(), "初始是收起的");
    F.tzOpen();
    check((els.tz_list.innerHTML.match(/class="tz-item/g) || []).length === 5,
          "框里已有值时展开仍是全部 5 项（不被框里的值过滤掉）",
          String((els.tz_list.innerHTML.match(/class="tz-item/g) || []).length));
    check(isOpen(), "调 tzOpen() 后展开");
    check(/tz-item/.test(els.tz_list.innerHTML), "展开时列表已渲染（框里有值也不影响）");
    F.tzClose();
    check(!isOpen(), "tzClose() 收起");
    F.tzToggle({ stopPropagation() {} });
    check(isOpen(), "点箭头（tzToggle）展开");
    F.tzToggle({ stopPropagation() {} });
    check(!isOpen(), "再点箭头收起");

    console.log("③ 输入即筛选");
    els.sys_tz.value = "tok";
    F.tzInput();
    check(isOpen(), "输入时保持展开");
    const filtered = els.tz_list.innerHTML;
    check(/Asia\/Tokyo/.test(filtered) && !/America\/New_York/.test(filtered), "只留下匹配项", filtered.slice(0, 60));
    check(!/tz-grp/.test(filtered), "筛选时不显示分组标题");
    F.tzRender("zzz");
    check(/没有匹配的时区/.test(els.tz_list.innerHTML), "无匹配时给出提示");

    console.log("④ 点条目即选中并收起");
    els.sys_tz.value = "Asia/Shanghai";
    F.tzRender("");
    F.tzOpen();
    fireList("mousedown", itemEl("Asia/Tokyo"));
    check(els.sys_tz.value === "Asia/Tokyo", "点条目后输入框变成该时区", els.sys_tz.value);
    check(!isOpen(), "选完自动收起");

    console.log("⑤ 键盘：Esc 收起 / Enter 选第一个匹配");
    els.sys_tz.value = "euro";
    F.tzOpen();
    F.tzKey({ key: "Escape", target: els.sys_tz, preventDefault() {} });
    check(!isOpen(), "Esc 收起");
    els.sys_tz.value = "new";
    F.tzOpen();
    F.tzKey({ key: "Enter", target: els.sys_tz, preventDefault() {} });
    check(els.sys_tz.value === "America/New_York", "Enter 选中第一个匹配（America/New_York）", els.sys_tz.value);
    check(!isOpen(), "Enter 后收起");

    console.log("⑥ 点面板其他地方收起");
    els.sys_tz.value = "UTC";
    F.tzOpen();
    docHandlers.forEach(fn => fn({ target: { _inside: false } }));
    check(!isOpen(), "点外部收起");
    F.tzOpen();
    docHandlers.forEach(fn => fn({ target: { _inside: true } }));
    check(isOpen(), "点自己内部不收起");

    console.log("⑦ 保存前按列表校验");
    posted = []; toasts.length = 0;
    els.sys_tz.value = "Asia/Shangai";     // 故意错一个字母
    await F.sysTimeSave();
    check(posted.length === 0, "打错时不发请求（本地就拦下）", JSON.stringify(posted));
    check(/没有这个时区/.test(toasts[0] ? toasts[0][0] : ""), "给出明确提示", JSON.stringify(toasts));
    els.sys_tz.value = "Asia/Tokyo";
    await F.sysTimeSave();
    check(posted.length === 1 && posted[0][0] === "/api/system/time" && posted[0][1].tz === "Asia/Tokyo",
          "合法时区正常提交", JSON.stringify(posted));
    els.sys_tz.value = "   ";
    await F.sysTimeSave();
    check(posted.length === 1 && /请选择或输入时区/.test(toasts[toasts.length - 1][0]), "空值给出提示且不提交");

    console.log("⑧ 列表拉不到时不挡人（仍可手输）");
    global.api = async () => { throw new Error("network"); };
    const f2 = new Function(PRELUDE + srcs.join("\n") + "\nreturn {loadTimezones: loadTimezones, sysTimeSave: sysTimeSave, tzRender: tzRender};")();
    await f2.loadTimezones();
    check(/读取失败/.test(els.tz_list.innerHTML), "列表读不到时下拉里给出说明", els.tz_list.innerHTML.slice(0, 50));
    posted = []; toasts.length = 0;
    els.sys_tz.value = "Asia/Kathmandu";
    await f2.sysTimeSave();
    check(posted.length === 1 && posted[0][1].tz === "Asia/Kathmandu", "无列表时不做本地拦截，直接提交", JSON.stringify(posted));

    console.log("⑨ IPv6：当前状态那个按钮标「（当前）」并禁用");
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

    console.log("⑩ NTP：按状态只显示该做的那个");
    F.renderSysTime({ time: { timezone: "Asia/Shanghai", time: "2026-09-16 23:00:00", ntp: true } });
    check(els.btn_ntp_off.style.display === "inline-block" && els.btn_ntp_on.style.display === "none", "NTP 已开 → 只给「关闭 NTP」");
    check(/已开启/.test(els.sys_time.innerHTML), "状态行显示已开启");
    F.renderSysTime({ time: { timezone: "Asia/Shanghai", time: "x", ntp: false } });
    check(els.btn_ntp_on.style.display === "inline-block" && els.btn_ntp_off.style.display === "none", "NTP 已关 → 只给「开启 NTP」");
    F.renderSysTime({ time: { timezone: "Asia/Shanghai", time: "x", ntp: null } });
    check(els.btn_ntp_on.style.display === "inline-block" && els.btn_ntp_off.style.display === "inline-block",
          "状态未知 → 两个按钮都留着（不给用户死路）");

    console.log("⑪ NTP 开不起来时给一键安装入口（Debian 最小镜像实测 NTP not supported）");
    posted = []; toasts.length = 0; cfm = null;
    global.api = async (m, p, body) => {
        posted.push([p, body]);
        if (body && body.install) return { ok: true, msg: "NTP 自动同步已开启" };
        const e = new Error("Failed to set ntp: NTP not supported｜系统里没有 NTP 服务（systemd-timesyncd / chrony 都没有）。面板可以一键安装 systemd-timesyncd 并开启");
        e.fix = "install_ntp";
        throw e;
    };
    await F.sysNtpToggle(true);
    check(posted.length === 1 && posted[0][1].install === false, "先按原样试一次开启（install=false）", JSON.stringify(posted));
    check(cfm !== null && /安装 NTP 服务/.test(cfm.title), "失败后弹出「安装 NTP 服务」确认框", cfm ? cfm.title : "未弹框");
    check(cfm && /systemd-timesyncd/.test(cfm.msg), "说明里讲清楚要装什么", cfm ? cfm.msg.slice(0, 40) : "");
    cfm.onOk();
    await new Promise(r => setTimeout(r, 10));
    check(posted.length === 2 && posted[1][1].install === true && posted[1][1].enable === true,
          "点确认后带 install=true 再请求一次（真正去装）", JSON.stringify(posted[1]));
    check(toasts.some(x => /NTP 自动同步已开启/.test(x[0])), "装完提示成功", JSON.stringify(toasts.slice(-1)));
    check(loaded >= 1, "操作完会刷新系统页状态");

    console.log(failures === 0 ? "\n全部通过 ✓" : "\n失败 " + failures + " 项 ✗");
    process.exit(failures === 0 ? 0 : 1);
})();
