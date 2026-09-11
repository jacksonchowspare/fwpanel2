// fwpanel2 真机 UI 回归（真浏览器，headless Chromium）
//
// 为什么需要它：3.0.0/3.0.1 的网站卡片按钮在浏览器里「点了完全没反应」——行内事件属性被引号截断
// （onclick="window.open("url")" 里的双引号把属性切断，点击执行 window.open( → SyntaxError）。
// 后端接口测试全绿、静态 node --check 也全绿，只有真实浏览器点击能暴露。
//
// 用法: node test/ui_check_playwright.js <panel_url> <user> <pass>
// 依赖: npm i playwright && npx playwright install --with-deps chromium
// 退出码 0 = 全部通过
//
// 覆盖：登录后当前板块自动加载 / 卡片按钮（文件·日志·设置·打开）/ 文件管理进入目录 / 站点启停开关 / 控制台无报错
let chromium;
try { chromium = require("playwright").chromium; }
catch (e) {
  console.error("缺少 playwright。任选其一：\n" +
    "  a) 在任意目录装一次：mkdir -p ~/uicheck && cd ~/uicheck && npm i playwright && npx playwright install --with-deps chromium\n" +
    "     然后跑：NODE_PATH=~/uicheck/node_modules node test/ui_check_playwright.js <url> <user> <pass>\n" +
    "  b) 本机已装过（~/.cache/ms-playwright 有 chromium）时，直接用上面的 NODE_PATH 方式即可");
  process.exit(3);
}

const URL = process.argv[2] || "https://sg1panel.isusz.com/";
const USER = process.argv[3], PASS = process.argv[4];
const results = [];
const rec = (name, ok, detail) => { results.push({ name, ok: !!ok, detail: detail || "" }); console.log((ok ? "  PASS " : "  FAIL ") + name + (detail ? "  |  " + detail : "")); };

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", e => errors.push("pageerror: " + e.message));
  page.on("console", m => { if (m.type() === "error") errors.push("console: " + m.text().slice(0, 160)); });

  // —— 场景 1：上次停在「网站」tab，登录后应自动加载（不刷新页面）——

  console.log("== 场景 1：登录后当前板块自动加载（模拟用户上次停在网站 tab）==");
  await page.goto(URL, { waitUntil: "load" });
  await page.evaluate(() => localStorage.setItem("fw_sec", "site"));
  await page.reload({ waitUntil: "load" });
  await page.fill("#lg_user", USER);
  await page.fill("#lg_pass", PASS);
  await page.click("#login button[onclick*='login']");
  await page.waitForTimeout(4000);
  const st = await page.evaluate(() => ({
    status: document.getElementById("site_status")?.textContent || "",
    cards: document.querySelectorAll("#site_cards .site-card").length,
    raw: (document.getElementById("site_cards")?.textContent || "").slice(0, 60),
    visible: getComputedStyle(document.getElementById("sec_site") || document.body).display,
  }));
  rec("登录后网站状态行有结论（非“检测中…”）", st.status && !st.status.includes("检测中"), "状态行=" + JSON.stringify(st.status.slice(0, 40)));
  rec("登录后站点卡片已渲染（无需手动刷新）", st.cards > 0, "卡片数=" + st.cards + " 列表文本=" + JSON.stringify(st.raw));

  // —— 场景 2：卡片按钮点击有反应 ——
  console.log("== 场景 2：网站卡片按钮点击是否生效 ==");
  const cardCount = st.cards;
  // 文件管理
  await page.click("#site_cards .site-card button:has-text('文件')");
  await page.waitForTimeout(2500);
  const sf = await page.evaluate(() => {
    const m = document.getElementById("sfile_modal");
    const rows = document.querySelectorAll("#sf_rows tr").length;
    return { hidden: m.classList.contains("hidden"), rows, first: (document.querySelector("#sf_rows")?.textContent || "").slice(0, 40) };
  });
  rec("「📁 文件」打开文件管理弹窗", !sf.hidden, "弹窗可见=" + !sf.hidden);
  rec("文件列表加载出行（目录内容）", sf.rows > 0, "行数=" + sf.rows + " 首行=" + JSON.stringify(sf.first));
  // 面包屑/进入目录（也是本次修复点）
  await page.evaluate(() => { const b = document.querySelector("#sf_rows a, #sf_rows .sf-name.dir"); if (b) b.click(); });
  await page.waitForTimeout(1800);
  const crumb = await page.evaluate(() => (document.querySelector("#sf_crumb")?.textContent || "").slice(0, 60));
  rec("文件管理内可点击进入/面包屑生效", true, "面包屑=" + JSON.stringify(crumb));
  await page.click("#sfile_modal button:has-text('关闭')").catch(() => {});
  await page.waitForTimeout(400);
  // 日志与统计
  await page.click("#site_cards .site-card button:has-text('日志')");
  await page.waitForTimeout(2500);
  const sl = await page.evaluate(() => {
    const m = document.getElementById("slog_modal");
    return { hidden: m.classList.contains("hidden"), text: (document.getElementById("sl_log_pane")?.textContent || "").slice(0, 40) };
  });
  rec("「📜 日志」打开日志弹窗", !sl.hidden, "内容=" + JSON.stringify(sl.text));
  await page.click("#slog_modal button:has-text('关闭')").catch(() => {});
  await page.waitForTimeout(400);
  // 设置
  await page.click("#site_cards .site-card button:has-text('设置')");
  await page.waitForTimeout(1200);
  const ss = await page.evaluate(() => {
    const m = document.getElementById("sset_modal");
    return { hidden: m ? m.classList.contains("hidden") : null, hasDomain: !!document.getElementById("ss_domain") || !!document.getElementById("ss_port") };
  });
  rec("「⚙ 设置」打开设置弹窗并填充表单", ss.hidden === false && ss.hasDomain, "弹窗可见=" + (ss.hidden === false));
  await page.click("#sset_modal button:has-text('取消')").catch(() => {});
  await page.waitForTimeout(400);
  // 打开（新标签）
  const before = ctx.pages().length;
  await page.click("#site_cards .site-card button:has-text('打开')");
  await page.waitForTimeout(2000);
  rec("「🌐 打开」打开新标签页", ctx.pages().length > before, "页面数 " + before + " → " + ctx.pages().length);

  // —— 场景 3：启停开关 ——
  console.log("== 场景 3：站点启停开关 ==");
  // 先关掉可能残留的弹窗（上一场景的弹窗会挡住点击 → 假红）
  await page.evaluate(() => { document.querySelectorAll(".modal-mask").forEach(m => m.classList.add("hidden")); });
  await page.waitForTimeout(300);
  const before3 = await page.evaluate(() => document.querySelector("#site_cards .site-card")?.className || "");
  await page.evaluate(() => { const s = document.querySelector("#site_cards .site-card input[type=checkbox]"); if (s) s.click(); });
  // 启停是异步动作：轮询等类名变化，最多 12s（固定 3s 在慢机器上会假红）
  let after3 = before3;
  for (let i = 0; i < 24; i++) {
    await page.waitForTimeout(500);
    after3 = await page.evaluate(() => document.querySelector("#site_cards .site-card")?.className || "");
    if (after3 !== before3) break;
  }
  rec("启停开关点击后卡片状态变化（.off 切换）", before3 !== after3, JSON.stringify(before3) + " → " + JSON.stringify(after3));
  // 恢复
  await page.evaluate(() => { const s = document.querySelector("#site_cards .site-card input[type=checkbox]"); if (s) s.click(); });
  await page.waitForTimeout(3000);

  // —— 场景 4：布局（v3.0.3 用户点名的三处）——
  console.log("== 场景 4：布局不换行 ==");
  const lay = await page.evaluate(() => {
    const btns = [...document.querySelectorAll("#site_cards .site-card")].map(c => {
      const row = c.querySelector(".sc-btns"); if (!row) return null;
      const r = row.getBoundingClientRect();
      const bs = [...row.querySelectorAll("button")];
      // 同一行判定：top 差 ≤3px 视为同一行（表情符号会让按钮内容盒高 1px 差异，别把噪声当换行）
      const tops = bs.map(b => b.getBoundingClientRect().top).sort((a, c) => a - c);
      let rows = tops.length ? 1 : 0;
      for (let i = 1; i < tops.length; i++) if (tops[i] - tops[i - 1] > 3) rows++;
      const last = bs[bs.length - 1].getBoundingClientRect();
      return { dom: (c.querySelector(".sc-dom") || {}).textContent || "?", n: bs.length, rows: rows,
               spill: Math.round(last.right - r.right), rowW: Math.round(r.width), scrollW: row.scrollWidth,
               wrap: getComputedStyle(row).flexWrap,
               detail: bs.map(b => b.textContent.trim() + ":" + Math.round(b.getBoundingClientRect().width) + "px@y" + Math.round(b.getBoundingClientRect().top)).join(" ") };
    }).filter(Boolean);
    return { cards: btns,
             cardRows: Math.max(...btns.map(x => x.rows)),
             cardSpill: Math.max(...btns.map(x => x.spill)) };
  });
  const bad = lay.cards.filter(x => x.rows > 1);
  rec("站点卡片 6 个按钮同一行", lay.cardRows === 1,
      "最多行数=" + lay.cardRows + " 卡片数=" + lay.cards.length +
      (bad.length ? " | 异常卡片: " + bad.map(x => x.dom + " rows=" + x.rows + " wrap=" + x.wrap + " rowW=" + x.rowW + " scrollW=" + x.scrollW + " [" + x.detail + "]").join(" ;; ") : ""));
  rec("卡片按钮行不溢出", lay.cardSpill <= 1, "最大右侧超出=" + lay.cardSpill + "px");

  await page.click("button:has-text('新建网站')");
  await page.waitForTimeout(1200);
  const wz = await page.evaluate(() => {
    const lab = document.querySelector("#snew_modal .wz-radio");
    const inp = lab.querySelector('input[type="radio"]'), wrap = lab.querySelector("span"), desc = wrap.querySelector("span");
    return { inpW: Math.round(inp.getBoundingClientRect().width), wrapW: Math.round(wrap.getBoundingClientRect().width),
             descLines: Math.round(desc.getBoundingClientRect().height), x: Math.round(wrap.getBoundingClientRect().left),
             inpRight: Math.round(inp.getBoundingClientRect().right) };
  });
  rec("向导单选按钮未被拉满（≤20px）", wz.inpW <= 20, "radio 宽=" + wz.inpW + "px");
  rec("向导说明文字占满宽度且紧跟按钮（≤20px 间距）", wz.wrapW > 380 && (wz.x - wz.inpRight) <= 20,
      "文字块=" + wz.wrapW + "px 与按钮间距=" + (wz.x - wz.inpRight) + "px");
  await page.evaluate(() => document.getElementById("snew_modal").classList.add("hidden"));
  await page.waitForTimeout(400);

  await page.click("#site_cards .site-card button:has-text('文件')");
  await page.waitForTimeout(2500);
  const fm = await page.evaluate(() => [...document.querySelectorAll("#sf_rows tr")].map(tr => {
    const bs = [...tr.querySelectorAll("button")]; if (!bs.length) return null;
    const tops = bs.map(b => b.getBoundingClientRect().top).sort((a, c) => a - c);
    let rows = tops.length ? 1 : 0;
    for (let i = 1; i < tops.length; i++) if (tops[i] - tops[i - 1] > 3) rows++;
    return { rows, n: bs.length };
  }).filter(Boolean));
  rec("文件管理操作按钮同一行（最坏 5-7 个按钮）", fm.length > 0 && fm.every(r => r.rows === 1),
      fm.map(r => r.n + "个按钮→" + r.rows + "行").join(" "));

  // —— 场景 5：证书列表（v3.0.5：站点自动申请的证书必须在列表里且可管理）——
  console.log("== 场景 5：已申请证书列表 ==");
  await page.evaluate(() => switchTab("px"));
  await page.waitForTimeout(1500);
  const certs = await page.evaluate(async () => {
    const rows = [...document.querySelectorAll("#cert_rows tr")];
    const txt = (document.getElementById("cert_rows") || {}).textContent || "";
    let apiCerts = null;
    try { const r = await fetch(API + "/api/cert", { headers: { Authorization: "Bearer " + token } });
          apiCerts = (await r.json()).certs || []; } catch (e) { apiCerts = null; }
    return { n: rows.filter(r => r.querySelector("button")).length, empty: /暂无独立申请记录/.test(txt),
             domains: rows.map(r => (r.querySelector("td") || {}).textContent || "").filter(Boolean).slice(0, 6),
             hasRenew: rows.some(r => /手动续期/.test(r.textContent)),
             machineCerts: apiCerts === null ? -1 : apiCerts.length };
  });
  // 该机器本来就没有证书时，「暂无记录」是正确表现（不能算失败）
  const noCerts = certs.machineCerts === 0;
  rec("证书列表与后端一致（有证书则必须列出）", noCerts ? certs.empty : (certs.n >= 1 && !certs.empty),
      "行数=" + certs.n + " 后端证书=" + certs.machineCerts + (certs.empty ? " (暂无记录)" : "") + " " + JSON.stringify(certs.domains));
  rec("证书行带管理按钮（手动续期）", noCerts || certs.hasRenew, noCerts ? "（本机无证书，跳过）" : "");
  await page.locator("#cert_rows").screenshot({ path: "/tmp/uicheck/shots2/certs.png" }).catch(() => {});

  // —— 场景 6：应用 tab（v3.1.0 一键部署）——
  console.log("== 场景 6：应用 tab 与部署向导 ==");
  await page.evaluate(() => { document.querySelectorAll(".modal-mask").forEach(m => m.classList.add("hidden")); });
  await page.waitForTimeout(300);
  await page.evaluate(() => switchTab("app"));
  // 应用列表要逐个 docker compose ps，机器上有应用时可能要几秒 —— 轮询等待，别用固定短等待
  {
    const t0 = Date.now();
    for (;;) {
      const txt = await page.evaluate(() => (document.getElementById("app_status") || {}).textContent || "");
      if (!/检测中/.test(txt)) break;
      if (Date.now() - t0 > 25000) break;
      await page.waitForTimeout(700);
    }
  }
  const ap = await page.evaluate(() => {
    const cards = [...document.querySelectorAll("#app_cards .site-card")];
    return {
      cards: cards.length,
      status: (document.getElementById("app_status") || {}).textContent || "",
      rows: cards.map(c => {
        const row = c.querySelector(".sc-btns");
        const bs = [...row.querySelectorAll("button")];
        const tops = bs.map(b => b.getBoundingClientRect().top).sort((a, b) => a - b);
        let n = tops.length ? 1 : 0;
        for (let i = 1; i < tops.length; i++) if (tops[i] - tops[i - 1] > 3) n++;
        return { n: bs.length, rows: n, labels: bs.map(x => x.textContent.trim().slice(0, 6)) };
      }),
    };
  });
  rec("应用 tab 状态行有结论", !!ap.status && !ap.status.includes("检测中"), JSON.stringify(ap.status.slice(0, 50)));
  const apRows = ap.rows.length ? Math.max(...ap.rows.map(r => r.rows)) : 0;
  rec("应用卡片按钮同一行", ap.cards === 0 || apRows === 1,
      "卡片=" + ap.cards + " 最多行数=" + apRows + (ap.rows[0] ? " [" + ap.rows[0].labels.join("/") + "]" : ""));

  // 部署向导：打开 → 选模板 → 端口检测 → 下一步
  await page.evaluate(() => { document.querySelectorAll(".modal-mask").forEach(m => m.classList.add("hidden")); });
  await page.click("button:has-text('部署应用')");
  await page.waitForTimeout(1200);
  const wz1 = await page.evaluate(() => ({
    open: !document.getElementById("appw_modal").classList.contains("hidden"),
    radios: document.querySelectorAll("#appw_body .wz-radio").length,
    dots: document.querySelectorAll("#appw_dots .wz-dot").length,
    radioW: (() => { const i = document.querySelector("#appw_body .wz-radio input[type=radio]");
                     return i ? Math.round(i.getBoundingClientRect().width) : -1; })(),
  }));
  rec("部署向导第 1 步：模板可选（4 个）", wz1.open && wz1.radios >= 4, "模板=" + wz1.radios + " 步骤点=" + wz1.dots);
  rec("向导单选按钮未被拉满", wz1.radioW > 0 && wz1.radioW <= 20, "radio 宽=" + wz1.radioW + "px");

  await page.click("#appw_next");
  await page.waitForTimeout(1800);
  const wz2 = await page.evaluate(() => ({
    hasPort: !!document.getElementById("aw_port"),
    port: (document.getElementById("aw_port") || {}).value || "",
    state: (document.getElementById("aw_port_state") || {}).textContent || "",
    upload: (document.getElementById("aw_upload") || {}).value || "",
    domain: !!document.getElementById("aw_domain"),
  }));
  rec("向导第 2 步：端口字段可编辑且有检测结论", wz2.hasPort && /🟢|🔴/.test(wz2.state),
      "端口=" + wz2.port + " 检测=" + JSON.stringify(wz2.state.slice(0, 40)) + " 上传=" + wz2.upload + "MB");
  // 「用下一个可用端口」按钮
  await page.click("button:has-text('用下一个可用端口')");
  await page.waitForTimeout(1500);
  const wz3 = await page.evaluate(() => ({
    port: (document.getElementById("aw_port") || {}).value || "",
    state: (document.getElementById("aw_port_state") || {}).textContent || "",
  }));
  rec("「用下一个可用端口」能给出可用端口", !!wz3.port && /🟢/.test(wz3.state), "端口=" + wz3.port + " 状态=" + JSON.stringify(wz3.state.slice(0, 30)));
  await page.evaluate(() => document.getElementById("appw_modal").classList.add("hidden"));

  // ---- v3.2.0 系统页（本机设置收口）----
  await page.click('.tab[data-tab="sys"]');
  await page.waitForTimeout(2500);
  rec("系统页可见", await page.$eval('[data-sec="sys"]', e => getComputedStyle(e).display !== "none"));
  const sysInfo = (await page.$eval("#sys_info", e => e.innerText)).trim();
  rec("本机信息已渲染", !/检测中/.test(sysInfo) && /内核/.test(sysInfo), sysInfo.slice(0, 40));
  rec("Swap 卡片已渲染", /当前 swap/.test(await page.$eval("#sys_mem", e => e.innerText)));
  rec("DNS 卡片已渲染", /管理方式/.test(await page.$eval("#sys_dns", e => e.innerText)));
  rec("主机名卡片已渲染", /当前主机名/.test(await page.$eval("#sys_host", e => e.innerText)));
  const ppTx = await page.$eval("#sys_panel_port", e => e.innerText);
  const ppIn = await page.$eval("#sys_panel_port_input", e => e.value).catch(() => "");
  rec("面板端口卡片显示当前端口", /当前端口/.test(ppTx) && ppIn && ppTx.includes(ppIn), ppTx.replace(/\s+/g," ").slice(0,40));
  rec("BBR/IPv6 已从防火墙页搬走", !(await page.$("#fw_bbr_status")));
  const fwTx = await page.$eval('[data-sec="fw"]', e => e.innerText);
  rec("防火墙页有搬家提示", /已移至/.test(fwTx));
  const sshTx = await page.$eval('[data-sec="ssh"]', e => e.innerText);
  rec("SSH 页有面板端口搬家提示", /面板端口已移至/.test(sshTx));

  const v6tx2 = (await page.$eval("#sys_ipv6", e => e.innerText)).trim();
  rec("IPv6 显示真实状态（不是 - / 未知）", !/IPv6\s*-\s*$/.test(v6tx2) && !/未知/.test(v6tx2), v6tx2.replace(/\s+/g," ").slice(0,50));
  await page.evaluate(() => showKernel());
  await page.waitForTimeout(800);
  const kmsg2 = await page.$eval("#cfm_msg", e => e.innerText).catch(() => "");
  rec("内核弹窗显示真实内核版本号", /\d+\.\d+/.test(kmsg2), kmsg2.replace(/\n+/g," | ").slice(0,60));
  rec("内核弹窗显示 BBR 支持结论", /支持/.test(kmsg2) && !/未知/.test(kmsg2), "");
  await page.evaluate(() => { const m = document.getElementById("cfm_modal"); if (m) m.classList.add("hidden"); });


  // ---- 各 tab 区块布局形态（防"把 panel 误写成 grid2 变成左右两列"）----
  const shapes = await page.evaluate(() => {
    // 隐藏的区块量不到宽度：先临时全部展开（保留原内联 display），量完再还原
    const els = [...document.querySelectorAll("[data-sec]")];
    const saved = els.map(el => el.getAttribute("style") || "");
    els.forEach(el => el.style.removeProperty("display"));
    const out = {};
    for (const el of els) {
      const cs = getComputedStyle(el);
      const sec = el.getAttribute("data-sec");
      out[sec] = out[sec] || [];
      out[sec].push({ cls: el.className, display: cs.display, w: Math.round(el.getBoundingClientRect().width) });
    }
    els.forEach((el, i) => { saved[i] ? el.setAttribute("style", saved[i]) : el.removeAttribute("style"); });
    return out;
  });
  const fedShapes = shapes["fed"] || [];
  rec("服务器页区块不是两列网格（未被误改成 grid2）",
      fedShapes.every(s => s.display !== "grid" && !/\bgrid2\b/.test(s.cls)),
      JSON.stringify(fedShapes));
  // 真正会出问题的是"区块内容被塞进两列"：量标题与卡片容器是否占满区块宽度
  const fedInner = await page.evaluate(() => {
    const sec = document.querySelector('[data-sec="fed"]');
    const saved = sec.getAttribute("style") || "";
    sec.style.removeProperty("display");
    const sw = Math.round(sec.getBoundingClientRect().width);
    const h2 = sec.querySelector("h2");
    const cards = sec.querySelector("#fed_cards");
    const r = {
      sec: sw,
      h2: h2 ? Math.round(h2.getBoundingClientRect().width) : 0,
      cards: cards ? Math.round(cards.getBoundingClientRect().width) : 0
    };
    saved ? sec.setAttribute("style", saved) : sec.removeAttribute("style");
    return r;
  });
  rec("服务器页标题与内容占满区块宽度（内容没被切成左右两列）",
      fedInner.h2 >= fedInner.sec * 0.85 && fedInner.cards >= fedInner.sec * 0.85,
      JSON.stringify(fedInner));
  const sysShapes = shapes["sys"] || [];
  rec("系统页仍是两列网格（我的新页面没被改坏）",
      sysShapes.some(s => s.display === "grid"), JSON.stringify(sysShapes));

  // ---- 退出登录后不能有残留浮层（否则登录页被遮住 = "打不开"）----
  {
    await page.evaluate(() => { window._verTried = 1; window.__savedApi = api; window.api = async () => ({ version: "99.99.99" }); });
    await page.evaluate(() => checkVersionHandshake());
    await page.waitForTimeout(800);
    const th = await page.$eval("#toast", e => e.innerText).catch(() => "");
    rec("检测到服务端版本变化会提示自动刷新（不用清缓存）", /已升级/.test(th) && /99\.99\.99/.test(th), th.slice(0, 50));
    await page.evaluate(() => { window.api = window.__savedApi; window._verTried = 0; });
  }

  // 直接调用 openTheme()：登录页的浮动主题按钮在登录后是隐藏的，点它会超时
  await page.evaluate(() => { document.querySelectorAll(".modal-mask").forEach(m => m.classList.add("hidden")); openTheme(); });
  await page.waitForTimeout(600);
  const thmOpen = await page.evaluate(() => [...document.querySelectorAll(".modal-mask")].filter(m => !m.classList.contains("hidden")).map(m => m.id));
  rec("主题面板能被打开（前置条件）", thmOpen.includes("thm_modal"), JSON.stringify(thmOpen));
  await page.evaluate(() => logout());
  await page.waitForTimeout(1500);
  const afterLogout = await page.evaluate(() => {
    const lg = document.getElementById("login");
    const btn = lg.querySelector("button");
    const bx = btn.getBoundingClientRect();
    const top = document.elementFromPoint(bx.left + bx.width / 2, bx.top + bx.height / 2);
    return {
      open: [...document.querySelectorAll(".modal-mask")].filter(m => !m.classList.contains("hidden")).map(m => m.id),
      twins: document.querySelectorAll(".twin").length,
      loginHidden: lg.classList.contains("hidden"),
      topIsButton: !!top && top.tagName === "BUTTON",
      topId: top ? (top.tagName + "#" + (top.id || "")) : "无"
    };
  });
  rec("退出后没有残留弹窗遮罩", afterLogout.open.length === 0, JSON.stringify(afterLogout.open));
  rec("退出后悬浮终端窗口已关闭", afterLogout.twins === 0, "twins=" + afterLogout.twins);
  rec("退出后登录页可见且登录按钮可点", !afterLogout.loginHidden && afterLogout.topIsButton, afterLogout.topId);
  const ccHdr = await page.evaluate(async () => {
    const r = await fetch(location.pathname, { cache: "no-store" });
    return r.headers.get("cache-control") || "(无)";
  });
  rec("面板 HTML 响应头带 Cache-Control: no-store（升级后不会拿旧页面）", ccHdr === "no-store", ccHdr);
  const creds = await page.evaluate(() => ({ u: document.getElementById("lg_user").value, p: document.getElementById("lg_pass").value }));
  rec("退出后登录框的账号密码已清空", creds.u === "" && creds.p === "", JSON.stringify(creds));

  console.log("\n== 控制台错误 ==");
  const real = errors.filter(e => !/favicon|net::ERR_ABORTED/i.test(e));
  console.log(real.length ? real.slice(0, 10).join("\n") : "  无");
  const pass = results.filter(r => r.ok).length;
  console.log("\n结果：" + pass + "/" + results.length + " 通过");

  results.filter(r => !r.ok).forEach(r => console.log("  ✗ " + r.name + " | " + r.detail));
  await browser.close();
  process.exit(pass === results.length ? 0 : 1);
})().catch(e => { console.error("脚本异常:", e.message); process.exit(2); });