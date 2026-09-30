/* Integrity dashboard client. Polls /api/status + /api/history every 1s. No deps. */
const $ = id => document.getElementById(id);
const shortH = h => (!h || h.length < 16) ? (h || "-") : h.slice(0, 12) + "…" + h.slice(-6);

async function get(p) {
  const r = await fetch(p, { cache: "no-store" });
  if (!r.ok) throw new Error(p + " " + r.status);
  return r.json();
}

function setClock() {
  const d = new Date();
  $("clock").textContent = d.toLocaleTimeString();
}

function renderStatus(s) {
  const st = $("state");
  st.textContent = s.state;
  st.className = "state " + s.state;
  $("verdict").textContent = s.verdict;
  $("component").textContent = s.component;
  $("seq").textContent = s.seq;
  $("cycle").textContent = s.cycle;
  $("tx").textContent = s.tx;
  $("detail").textContent = s.detail;
  $("chainBadge").textContent = "chain: " + (s.chainUp ? "UP" : "fallback");
  $("hBase").textContent = shortH(s.expected); $("hBase").title = s.expected;
  $("hObs").textContent = shortH(s.observed); $("hObs").title = s.observed;
  $("hChain").textContent = shortH(s.chain); $("hChain").title = s.chain;
  $("hPrev").textContent = shortH(s.prevHash); $("hPrev").title = s.prevHash;
  mark("mBase", true);
  mark("mObs", s.observed === s.expected);
  mark("mChain", s.chain === s.expected);
  $("latencyNote").textContent =
    `measure ${s.measureMs}ms · verify ${s.verifyMs}ms · interval 5s · STALE after 12s`;
}

function mark(id, ok) {
  const e = $(id);
  e.textContent = ok ? "✓" : "✗";
  e.className = ok ? "ok" : "bad";
}

function renderHistory(h) {
  const tb = document.querySelector("#feed tbody");
  tb.innerHTML = "";
  const rows = h.slice(-14).reverse();
  for (const c of rows) {
    const tr = document.createElement("tr");
    tr.className = c.state;
    tr.innerHTML = `<td>${c.seq}</td><td>${c.state}</td><td>${c.verdict}</td>` +
      `<td>${c.component}</td><td>${c.measureMs}</td><td>${c.verifyMs}</td><td>${c.tx}</td>`;
    tb.appendChild(tr);
  }
  drawChart(h.slice(-40));
}

function drawChart(h) {
  const cv = $("chart"), ctx = cv.getContext("2d");
  const W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  const max = Math.max(10, ...h.map(c => Math.max(c.measureMs, c.verifyMs)));
  const grid = (v, col) => {
    ctx.strokeStyle = col; ctx.lineWidth = 1; ctx.beginPath();
    h.forEach((c, i) => {
      const x = (i / Math.max(1, h.length - 1)) * (W - 8) + 4;
      const y = H - 8 - (v(c) / max) * (H - 20);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  };
  // red dots where RED
  grid(c => c.measureMs, "#38bdf8");
  grid(c => c.verifyMs, "#a78bfa");
  ctx.fillStyle = "#8ea0c2"; ctx.font = "11px sans-serif";
  ctx.fillText("— measure", 8, 14); ctx.fillStyle = "#38bdf8"; ctx.fillRect(70, 6, 14, 3);
  ctx.fillStyle = "#8ea0c2"; ctx.fillText("— verify", 92, 14); ctx.fillStyle = "#a78bfa"; ctx.fillRect(150, 6, 14, 3);
  h.forEach((c, i) => {
    if (c.state !== "GREEN") {
      const x = (i / Math.max(1, h.length - 1)) * (W - 8) + 4;
      ctx.fillStyle = c.state === "RED" ? "#ef4444" : "#f59e0b";
      ctx.beginPath(); ctx.arc(x, 10, 3, 0, 7); ctx.fill();
    }
  });
}

async function attack(url, msgId) {
  try {
    const r = await fetch(url, { cache: "no-store" });
    const t = await r.text();
    try { $("attackMsg").textContent = JSON.parse(t).msg || t; }
    catch (e) { $("attackMsg").textContent = t; }
  } catch (e) { $("attackMsg").textContent = "failed: " + e; }
}

$("bTamperCfg").onclick = () => attack("/api/tamper/config");
$("bRestoreCfg").onclick = () => attack("/api/restore/config");
$("bTamperMem").onclick = () => attack("/tamper/memory?limit=999");
$("bClearMem").onclick = () => attack("/tamper/memory/clear");

async function tick() {
  try {
    const [s, h] = await Promise.all([get("/api/status"), get("/api/history")]);
    renderStatus(s); renderHistory(h);
  } catch (e) { $("detail").textContent = "engine unreachable: " + e; }
}
setClock(); setInterval(setClock, 1000);
tick(); setInterval(tick, 1000);
