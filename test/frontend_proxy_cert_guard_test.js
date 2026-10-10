#!/usr/bin/env node
/*
 * 反代证书/面板端口红线回归（v3.3.25）
 *
 * 背景（用户真机报障，2026-10-10 hk24）：用户在 IP:面板端口 上操作面板，建了一个指向面板端口、
 * 还没证书的反代 → 旧代码立刻挂上「反代目标端口-禁止公网直连」deny，当前页面所有 API 请求被
 * 丢包（用户说「卡住了」），刷新后公网彻底进不去；而 https://域名 又因为没证书被 443 兜底
 * ssl_reject_handshake 直接拒绝握手 → 两条入口全死，只剩 SSH。
 * 另一处同源问题：添加表单里的证书下拉写着「自动申请」，但 addProxy() 从来不申请证书
 * （payload 无 ssl 字段、也不调 action=ssl）→ 用户以为在申请，实际什么都没发生。
 *
 * 断言：
 *  ① 勾「立即申请证书」+ 未引用已有证书 → 添加成功后自动发起 action=ssl（带上新代理 id）；
 *  ② 引用了已有证书 → 不重复申请；③ 不勾选 → 不申请，但提示证书尚未申请；
 *  ④ 证书申请失败不能让用户以为添加失败（提示里要写清「代理已添加」+ 重试入口）；
 *  ⑤ 目标是面板自身端口时：无证书 → 红字警告写明 https 会握手失败 + 直连会被关闭；
 *     有证书 → 提示直连将关闭；端口不是面板端口 → 不提示；
 *  ⑥ 面板端口反代签好证书后：从 IP 进面板的页面要主动跳到 https://域名（否则页面「哑掉」）；
 *     已经是域名访问则不跳；
 *  ⑦ 源码级：证书下拉首项不再叫「自动申请」、SSL 列无证书时显示「未申请」、勾选框默认勾上。
 *
 * 用法：node frontend_proxy_cert_guard_test.js [index.html]
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

const NEEDED = ["addProxy", "proxyPanelPortWarnText", "pxPortWarn", "maybeJumpToPanelDomain"];
const srcs = {};
for (const n of NEEDED) {
  srcs[n] = extractFn(n);
  if (!srcs[n]) { console.log("提取 " + n + " 失败（函数被改名/删除？）"); process.exit(2); }
}

// 假环境：$ 返回可控元素；api/apiTask 记账；toast 记账；location 可控；setTimeout 立即执行但记账
function mkSandbox(opts) {
  opts = opts || {};
  const st = {
    els: {}, calls: [], toasts: [], timers: [],
    fetchImpl: null,
  };
  const el = (id) => (st.els[id] = st.els[id] || {
    id, value: "", checked: false, innerHTML: "", style: {}, classList: { add() {}, remove() {} },
  });
  ["px_domain", "px_host", "px_port", "px_scheme", "px_cert", "px_ws", "px_hsts", "px_issue_cert",
   "px_blockip", "px_panelport_warn", "pxe_cert", "pxe_panelport_warn"].forEach(el);
  st.els.px_scheme.value = "http";
  st.els.px_issue_cert.checked = opts.issueCert !== undefined ? opts.issueCert : true;
  st.els.px_blockip.checked = opts.blockIp !== undefined ? opts.blockIp : true;   // 表单默认勾上
  st.els.px_cert.value = opts.certRef || "";
  st.els.px_port.value = opts.port !== undefined ? String(opts.port) : "";
  st.els.px_domain.value = "hk24panel.isusz.com";
  st.els.px_host.value = "127.0.0.1";

  const sb = {
    console, JSON, Promise, Error, Math, Object, String, Number, RegExp, Array,
    setTimeout: (fn, ms) => { st.timers.push({ fn, ms }); return st.timers.length; },
    clearTimeout: () => {},
    location: { protocol: opts.protocol || "http:", hostname: opts.hostname || "101.32.40.219", href: "" },
    status: { panel_port: opts.panelPort !== undefined ? opts.panelPort : 42608 },
    $: el,
    toast: (msg, kind) => st.toasts.push({ msg: String(msg), kind }),
    loadProxy: () => st.calls.push("loadProxy"),
    renderRules: () => st.calls.push("renderRules"),
    loadCerts: () => st.calls.push("loadCerts"),
    loadCertOptions: async () => {},
    pxPage: 1,
    pxSearch: "",
    api: async (method, url, body) => {
      st.calls.push(method + " " + url);
      if (method === "POST" && url === "/api/proxy") st.postBody = body;
      if (!st.fetchImpl) return { ok: true, msg: "代理已添加", proxy: { id: "abc123", domain: "hk24panel.isusz.com", target_port: 42608 } };
      return st.fetchImpl(method, url, body);
    },
    apiTask: async (method, url, body) => {
      st.calls.push("TASK " + method + " " + url + " " + JSON.stringify(body));
      if (opts.taskFails) { const e = new Error("certbot 超时"); throw e; }
      return { msg: "证书已签发" };
    },
  };
  sb.globalThis = sb;
  vm.createContext(sb);
  vm.runInContext(Object.values(srcs).join("\n"), sb);
  return { sb, st };
}

async function run() {
  console.log("── ①~④ 添加反代时的证书申请语义（护栏一）");
  {
    // ① 勾选 + 无 cert_ref → 申请
    const { sb, st } = mkSandbox({ issueCert: true, certRef: "", port: 8080 });
    await sb.addProxy();
    const task = st.calls.find(c => c.startsWith("TASK"));
    check(!!task && task.includes("/api/proxy/abc123") && task.includes('"action":"ssl"'),
          "勾选「立即申请证书」→ 添加后自动发起证书申请", task);
    check(st.toasts.some(t => t.msg.includes("证书已签发") || t.msg.includes("已申请")),
          "申请成功后有成功提示");
  }
  {
    // ② 引用了已有证书 → 不申请
    const { sb, st } = mkSandbox({ issueCert: true, certRef: "*.example.com", port: 8080 });
    await sb.addProxy();
    check(!st.calls.some(c => c.startsWith("TASK")),
          "引用了已有证书 → 不重复申请（不调 action=ssl）");
  }
  {
    // ③ 不勾选 → 不申请，但明确提示证书尚未申请
    const { sb, st } = mkSandbox({ issueCert: false, certRef: "", port: 8080 });
    await sb.addProxy();
    check(!st.calls.some(c => c.startsWith("TASK")), "不勾选 → 不自动申请");
    check(st.toasts.some(t => /尚未申请/.test(t.msg) && /申请证书/.test(t.msg)),
          "不勾选时提示「证书尚未申请 + 申请入口」", JSON.stringify(st.toasts));
  }
  {
    // ④ 申请失败 → 提示里必须说清代理已添加 + 重试入口
    const { sb, st } = mkSandbox({ issueCert: true, certRef: "", port: 8080, taskFails: true });
    await sb.addProxy();
    const err = st.toasts.find(t => t.kind === "err");
    check(!!err && /代理已添加/.test(err.msg) && /申请证书/.test(err.msg),
          "证书申请失败时提示「代理已添加 + 可重试」，不误导成添加失败", JSON.stringify(st.toasts));
  }

  console.log("── ⑤ 目标是面板自身端口的红字警告（2-3）");
  {
    const { sb, st } = mkSandbox({ port: 42608, certRef: "", panelPort: 42608 });
    sb.pxPortWarn();
    const w = st.els.px_panelport_warn;
    check(w.style.display === "block" && /握手失败/.test(w.innerHTML) && /自动关闭/.test(w.innerHTML),
          "无证书 + 目标=面板端口 → 警告写明 https 握手失败与直连将被关闭", w.innerHTML);
  }
  {
    const { sb, st } = mkSandbox({ port: 42608, certRef: "hk24panel.isusz.com", panelPort: 42608 });
    sb.pxPortWarn();
    const w = st.els.px_panelport_warn;
    check(w.style.display === "block" && !/握手失败/.test(w.innerHTML) && /只能通过 https/.test(w.innerHTML),
          "有证书 + 目标=面板端口 → 只提示「直连将关闭、走 https」", w.innerHTML);
  }
  {
    const { sb, st } = mkSandbox({ port: 8080, certRef: "", panelPort: 42608 });
    sb.pxPortWarn();
    check(st.els.px_panelport_warn.style.display === "none" && st.els.px_panelport_warn.innerHTML === "",
          "目标不是面板端口 → 不显示任何警告");
  }

  console.log("── ⑥ 面板端口反代签好证书后的自动跳转（防页面「哑掉」）");
  {
    const { sb, st } = mkSandbox({ hostname: "101.32.40.219", panelPort: 42608 });
    const jumped = sb.maybeJumpToPanelDomain("hk24panel.isusz.com", 42608);
    check(jumped === true, "从 IP 访问 + 反代指向面板端口 → 决定跳转");
    check(st.timers.length === 1 && st.timers[0].ms === 2500, "延迟 2.5 秒再跳（先让提示可见）");
    st.timers[0].fn();
    check(sb.location.href === "https://hk24panel.isusz.com/",
          "跳转目标 = https://域名/", sb.location.href);
    check(st.toasts.some(t => /直连 IP:端口 已按设计关闭/.test(t.msg)),
          "跳转前有明确提示（说明为什么跳）");
  }
  {
    const { sb, st } = mkSandbox({ hostname: "hk24panel.isusz.com", panelPort: 42608 });
    check(sb.maybeJumpToPanelDomain("hk24panel.isusz.com", 42608) === false && st.timers.length === 0,
          "已经是域名访问 → 不跳转");
  }
  {
    const { sb, st } = mkSandbox({ hostname: "101.32.40.219", panelPort: 42608 });
    check(sb.maybeJumpToPanelDomain("app.example.com", 8080) === false && st.timers.length === 0,
          "反代目标不是面板端口（IP 直连不受影响）→ 不跳转");
  }

  console.log("── ⑧ 新建反代的「禁止 IP 直连」默认值（护栏三）");
  {
    const { sb, st } = mkSandbox({ issueCert: false, blockIp: true, port: 8080 });
    await sb.addProxy();
    check(!!st.postBody && st.postBody.block_ip === true,
          "表单默认勾选「禁止 IP 直连」→ 添加请求带 block_ip:true（新建即显示「禁止IP访问中」）",
          JSON.stringify(st.postBody));
  }
  {
    const { sb, st } = mkSandbox({ issueCert: false, blockIp: false, port: 8080 });
    await sb.addProxy();
    check(!!st.postBody && st.postBody.block_ip === false,
          "取消勾选 → block_ip:false（允许 IP 直连）", JSON.stringify(st.postBody));
  }

  console.log("── ⑦ 源码级：文案与默认值");
  check(/id="px_blockip" checked/.test(html),
        "添加表单存在「禁止 IP 直连」勾选框且默认勾上");
  check(/id="px_issue_cert" checked/.test(html), "添加表单的「立即申请证书」勾选框默认勾上");
  check(/<option value="">不引用已有证书（用本域名自己的）<\/option>/.test(js),
        "证书下拉首项不再写「自动申请」（改为不引用已有证书）");
  check(js.includes('let html = \'<option value="">不引用已有证书（用本域名自己的）</option>\';'),
        "certOptionsHtml 首项文案同步修正");
  check(/certText = `<span style="color:var\(--muted\)">未申请<\/span>`;/.test(js),
        "SSL 列在没有证书/未引用时显示「未申请」，不再是空单元格");

  console.log("\n" + (fail === 0 ? "全部通过" : "有失败") + `：${pass} 通过 / ${fail} 失败`);
  process.exit(fail === 0 ? 0 : 1);
}

run().catch(e => { console.log("测试自身异常：" + e.stack); process.exit(2); });
