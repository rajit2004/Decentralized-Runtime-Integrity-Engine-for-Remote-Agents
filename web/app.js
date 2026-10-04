/* Integrity dashboard client. Polls /api/status + /api/history every 1s. No deps. */
const $ = id => document.getElementById(id);
const shortH = h => (!h || h.length < 16) ? (h || "-") : h.slice(0, 12) + "…" + h.slice(-6);
let paused = false, sound = false, filter = "ALL", lastState = "", lastHist = [];
let audio = null;

async function get(p) {
  const r = await fetch(p, { cache: "no-store" });
  if (!r.ok) throw new Error(p + " " + r.status);
  return r.json();
}
async function text(p) {
  const r = await fetch(p, { cache: "no-store" });
  const t = await r.text();
  try { return JSON.parse(t).msg || t; } catch (e) { return t; }
}

function setClock() {
  $("clock").textContent = new Date().toLocaleTimeString();
}

function beep(bad) {
  if (!sound) return;
  try {
    audio = audio || new (window.AudioContext || window.webkitAudioContext)();
    const o = audio.createOscillator(), g = audio.createGain();
    o.connect(g); g.connect(audio.destination);
    o.frequency.value = bad ? 220 : 660;
    g.gain.setValueAtTime(0.12, audio.currentTime);
    o.start(); o.stop(audio.currentTime + (bad ? 0.3 : 0.12));
  } catch (e) {}
}

function flash(state) {
  const h = $("hero");
  h.classList.remove("flash-green", "flash-red");
  void h.offsetWidth;
  h.classList.add(state === "GREEN" ? "flash-green" : "flash-red");
}

function renderStatus(s) {
  if (s.state !== lastState && lastState !== "") { flash(s.state); beep(s.state !== "GREEN"); }
  lastState = s.state;
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
  setHash("hBase", "mBase", s.expected, true);
  setDiff("hObs", "mObs", s.expected, s.observed);
  setHash("hChain", "mChain", s.chain, s.chain === s.expected);
  setHash("hPrev", null, s.prevHash, true, true);
  $("latencyNote").textContent =
    `measure ${s.measureMs}ms · verify ${s.verifyMs}ms · interval 5s · STALE after 12s`;
  renderWitness(s.witness);
}

function renderWitness(w) {
  const c = $("witChain");
  if (!c) return;
  const m = $("witChainMark"), l = $("witLines"), h = $("witHead"), last = $("witLast");
  if (!w || !w.enabled) {
    c.textContent = "off"; m.textContent = "";
    l.textContent = "-"; h.textContent = "-"; last.textContent = "-";
    return;
  }
  c.textContent = w.chainOk ? "verified" : "BROKEN";
  m.textContent = w.chainOk ? "✓" : "✗";
  m.className = w.chainOk ? "ok" : "bad";
  l.textContent = w.lines;
  setHash("witHead", null, w.head, w.chainOk);
  last.textContent = "seq " + w.lastSeq + " · " + w.lastVerdict;
}

function setHash(codeId, markId, full, ok, neutral) {
  const c = $(codeId);
  c.textContent = shortH(full); c.title = full || "";
  c.dataset.copy = full || "";
  if (markId) {
    const m = $(markId);
    if (neutral || !full || full === "-") { m.textContent = ""; }
    else { m.textContent = ok ? "✓" : "✗"; m.className = ok ? "ok" : "bad"; }
  }
}

function setDiff(codeId, markId, base, obs) {
  const c = $(codeId);
  c.title = obs || "";
  c.dataset.copy = obs || "";
  if (!obs || obs === "-") { c.textContent = "-"; if (markId) $(markId).textContent = ""; return; }
  if (!base || base === "-" || base.length !== obs.length) {
    c.textContent = shortH(obs);
    if (markId) { const m = $(markId); m.textContent = base === obs ? "✓" : "✗"; m.className = base === obs ? "ok" : "bad"; }
    return;
  }
  let html = "", diff = 0;
  const show = obs.length > 24
    ? obs.slice(0, 12) + "…" + obs.slice(-6)
    : obs;
  // char-level diff on the displayed window: compare full strings, render window
  const win = obs.length > 24
    ? [[0, 12], [obs.length - 6, obs.length]]
    : [[0, obs.length]];
  let out = "";
  const escCh = ch => ch === "<" ? "&lt;" : ch === ">" ? "&gt;" : ch === "&" ? "&amp;" : ch;
  for (const [a, b] of win) {
    for (let i = a; i < b; i++) {
      out += (obs[i] === base[i])
        ? `<span class="same">${escCh(obs[i])}</span>`
        : `<span class="diff">${escCh(obs[i])}</span>`;
    }
    if (b !== obs.length) out += "…";
  }
  for (let i = 0; i < obs.length; i++) if (obs[i] !== base[i]) diff++;
  c.innerHTML = out;
  if (markId) { const m = $(markId); m.textContent = diff ? `✗ ${diff}` : "✓"; m.className = diff ? "bad" : "ok"; }
}

function renderTimeline(h) {
  const t = $("timeline");
  if (!t) return;
  t.innerHTML = "";
  for (const c of h.slice(-40)) {
    const d = document.createElement("span");
    d.className = "dot " + c.state;
    d.title = `seq ${c.seq} · ${c.state} · ${c.verdict}`;
    d.onclick = () => openDrawer(c.seq);
    t.appendChild(d);
  }
}

function renderDonut(h) {
  const cv = $("donut");
  if (!cv || !h.length) return;
  const fam = v => v === "OK" ? "ok" : v.startsWith("POLICY_") ? "policy" : v === "STALE" || v === "STALE_REPLAY" ? "stale" : "other";
  const counts = { ok: 0, policy: 0, stale: 0, other: 0 };
  for (const c of h) counts[fam(c.verdict)]++;
  const total = h.length;
  const parts = [
    ["ok", "OK", "#22c55e"], ["policy", "POLICY_*", "#ef4444"],
    ["stale", "STALE", "#f59e0b"], ["other", "other", "#38bdf8"]
  ];
  const ctx = cv.getContext("2d");
  const cx = 90, cy = 90, R = 70, r = 44;
  ctx.clearRect(0, 0, 180, 180);
  let a = -Math.PI / 2;
  for (const [k, label, col] of parts) {
    const frac = counts[k] / total;
    if (!frac) continue;
    ctx.beginPath();
    ctx.arc(cx, cy, R, a, a + frac * Math.PI * 2);
    ctx.arc(cx, cy, r, a + frac * Math.PI * 2, a, true);
    ctx.closePath();
    ctx.fillStyle = col;
    ctx.fill();
    a += frac * Math.PI * 2;
  }
  ctx.fillStyle = "#e5e7eb"; ctx.font = "bold 22px sans-serif"; ctx.textAlign = "center";
  ctx.fillText(total, cx, cy + 8);
  $("donutLegend").innerHTML = parts
    .map(([k, label, col]) => `<div><span class="sw" style="background:${col}"></span>${label}: ${counts[k]}</div>`)
    .join("");
}

function renderHistory(h) {
  lastHist = h;
  const tb = document.querySelector("#feed tbody");
  tb.innerHTML = "";
  const rows = h.filter(c => filter === "ALL" || c.state === filter).slice(-14).reverse();
  for (const c of rows) {
    const tr = document.createElement("tr");
    tr.className = c.state;
    tr.dataset.seq = c.seq;
    tr.innerHTML = `<td>${c.seq}</td><td>${c.state}</td><td>${c.verdict}</td>` +
      `<td>${c.component}</td><td>${c.measureMs}</td><td>${c.verifyMs}</td><td>${c.tx}</td>`;
    tr.onclick = () => openDrawer(c.seq);
    tb.appendChild(tr);
  }
  drawChart(h.slice(-40));
  renderTimeline(h);
  renderDonut(h.slice(-60));
}

function openDrawer(seq) {
  const c = lastHist.find(x => String(x.seq) === String(seq));
  if (!c) return;
  document.querySelectorAll("#feed tr").forEach(tr => tr.classList.toggle("sel", tr.dataset.seq === String(seq)));
  $("drawer").hidden = false;
  $("dTitle").textContent = `- seq ${c.seq} · cycle ${c.cycle} · ${c.state}`;
  $("dVerdict").textContent = c.verdict + " / " + c.component;
  setHash("dExp", null, c.expected, true, true);
  setHash("dObs", null, c.observed, true, true);
  setHash("dChain", null, c.chain, true, true);
  setHash("dPrev", null, c.prevHash, true, true);
  $("dTx").textContent = c.tx;
  $("dDetail").textContent = c.detail || "";
  $("drawer").scrollIntoView({ behavior: "smooth", block: "nearest" });
}
$("dClose").onclick = () => {
  $("drawer").hidden = true;
  document.querySelectorAll("#feed tr").forEach(tr => tr.classList.remove("sel"));
};

function drawChart(h) {
  const cv = $("chart"), ctx = cv.getContext("2d");
  const W = cv.width, H = cv.height;
  ctx.clearRect(0, 0, W, H);
  if (!h.length) return;
  const max = Math.max(10, ...h.map(c => Math.max(c.measureMs, c.verifyMs)));
  const line = (v, col) => {
    ctx.strokeStyle = col; ctx.lineWidth = 1.5; ctx.beginPath();
    h.forEach((c, i) => {
      const x = (i / Math.max(1, h.length - 1)) * (W - 8) + 4;
      const y = H - 8 - (v(c) / max) * (H - 20);
      i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
    });
    ctx.stroke();
  };
  line(c => c.measureMs, "#38bdf8");
  line(c => c.verifyMs, "#a78bfa");
  ctx.fillStyle = "#8ea0c2"; ctx.font = "11px sans-serif";
  ctx.fillText("- measure", 8, 14); ctx.fillStyle = "#38bdf8"; ctx.fillRect(70, 6, 14, 3);
  ctx.fillStyle = "#8ea0c2"; ctx.fillText("- verify", 92, 14); ctx.fillStyle = "#a78bfa"; ctx.fillRect(150, 6, 14, 3);
  h.forEach((c, i) => {
    if (c.state !== "GREEN") {
      const x = (i / Math.max(1, h.length - 1)) * (W - 8) + 4;
      ctx.fillStyle = c.state === "RED" ? "#ef4444" : "#f59e0b";
      ctx.beginPath(); ctx.arc(x, 10, 3, 0, 7); ctx.fill();
    }
  });
}

// ---- copy any hash ----
document.addEventListener("click", e => {
  const c = e.target.closest("code[data-copy]");
  if (!c || !c.dataset.copy) return;
  const done = () => { $("copyMsg").textContent = "copied " + shortH(c.dataset.copy); };
  if (navigator.clipboard) navigator.clipboard.writeText(c.dataset.copy).then(done).catch(() => fallbackCopy(c.dataset.copy, done));
  else fallbackCopy(c.dataset.copy, done);
});
function fallbackCopy(t, done) {
  const ta = document.createElement("textarea");
  ta.value = t; document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (e) {}
  ta.remove();
}

// ---- attack buttons ----
async function attack(url) {
  try { $("attackMsg").textContent = await text(url); }
  catch (e) { $("attackMsg").textContent = "failed: " + e + " (is the engine running?)"; }
}
$("bTamperCfg").onclick = () => attack("/api/tamper/config");
$("bRestoreCfg").onclick = () => attack("/api/restore/config");
$("bTamperMem").onclick = () => attack("/tamper/memory?limit=999");
$("bClearMem").onclick = () => attack("/tamper/memory/clear");

// ---- guided scenarios ----
function step(txt, cls) {
  const li = document.createElement("li");
  li.textContent = txt;
  if (cls) li.className = cls;
  $("scenarioSteps").appendChild(li);
  return li;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitFor(pred, timeoutMs, label) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try { const s = await get("/api/status"); if (pred(s)) return s; } catch (e) {}
    await sleep(1000);
  }
  throw new Error("timeout waiting for " + label);
}
async function runScenario(kind) {
  const btns = [$("bScenario"), $("bScenarioMem")];
  btns.forEach(b => b.disabled = true);
  $("scenarioSteps").innerHTML = "";
  try {
    if (kind === "config") {
      let li = step("Armed: flipping threshold 100 → 999 in config file…", "run");
      $("attackMsg").textContent = await text("/api/tamper/config");
      li.className = "done";
      li = step("Waiting for next 5s heartbeat to catch it…", "run");
      const red = await waitFor(s => s.state === "RED", 15000, "RED");
      li.textContent = `Caught: ${red.verdict} comp=${red.component} seq=${red.seq}`;
      li.className = "done";
      li = step("Restoring threshold 999 → 100…", "run");
      $("attackMsg").textContent = await text("/api/restore/config");
      li.className = "done";
      li = step("Waiting for GREEN recovery…", "run");
      const g = await waitFor(s => s.state === "GREEN", 15000, "GREEN");
      li.textContent = `Recovered: GREEN seq=${g.seq}. Baseline untouched - chain proves order, baseline proves good.`;
      li.className = "done";
    } else {
      let li = step("Armed: flipping memory limit → 999 (no file touched)…", "run");
      $("attackMsg").textContent = await text("/tamper/memory?limit=999");
      li.className = "done";
      li = step("Waiting for heartbeat…", "run");
      const red = await waitFor(s => s.state === "RED", 15000, "RED");
      li.textContent = `Caught: ${red.verdict} comp=${red.component} - memory blame without file edit`;
      li.className = "done";
      li = step("Clearing override…", "run");
      $("attackMsg").textContent = await text("/tamper/memory/clear");
      li.className = "done";
      li = step("Waiting for GREEN…", "run");
      const g = await waitFor(s => s.state === "GREEN", 15000, "GREEN");
      li.textContent = `Recovered: GREEN seq=${g.seq}.`;
      li.className = "done";
    }
  } catch (e) {
    step("Failed: " + e.message + " - is the engine running?", "fail");
  }
  btns.forEach(b => b.disabled = false);
}
$("bScenario").onclick = () => runScenario("config");
$("bScenarioMem").onclick = () => runScenario("mem");

// ---- toolbar ----
$("bPause").onclick = () => {
  paused = !paused;
  $("bPause").textContent = paused ? "▶ resume" : "⏸ pause";
};
$("bSound").onclick = () => {
  sound = !sound;
  $("bSound").textContent = sound ? "🔔 sound" : "🔇 sound";
};
$("bExport").onclick = async () => {
  try {
    const h = await get("/api/history");
    const blob = new Blob([JSON.stringify(h, null, 1)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "integrity-history.json";
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { $("attackMsg").textContent = "export failed: " + e; }
};
let present = false;
$("bPresent").onclick = () => {
  present = !present;
  document.body.classList.toggle("present", present);
  $("bPresent").textContent = present ? "✕ exit" : "⛶ present";
  try {
    if (present && document.documentElement.requestFullscreen) document.documentElement.requestFullscreen();
    else if (!present && document.fullscreenElement && document.exitFullscreen) document.exitFullscreen();
  } catch (e) {}
};
document.addEventListener("keydown", e => {
  if (e.key === "Escape" && present) $("bPresent").click();
  if (e.key === "p" && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== "INPUT") $("bPresent").click();
});
document.querySelectorAll(".chip.f").forEach(b => b.onclick = () => {
  document.querySelectorAll(".chip.f").forEach(x => x.classList.remove("on"));
  b.classList.add("on");
  filter = b.dataset.f;
  renderHistory(lastHist);
});

async function loadBaseline() {
  try {
    const b = await get("/api/baseline");
    $("baseLine").textContent =
      `agent ${b.agentId} · seq ${b.seq} · hComb ${shortH(b.hComb)} · prev ${shortH(b.prevHash)} (full hashes: click Hash-compare values to copy)`;
  } catch (e) { $("baseLine").textContent = "no baseline enrolled yet - run Enroll-Baseline"; }
}

async function tick() {
  if (paused) return;
  try {
    const [s, h] = await Promise.all([get("/api/status"), get("/api/history")]);
    document.body.classList.remove("dead");
    renderStatus(s); renderHistory(h);
  } catch (e) {
    document.body.classList.add("dead");
    $("detail").textContent = "engine unreachable: " + e + " (start it: scripts/run.ps1)";
  }
}
setClock(); setInterval(setClock, 1000);
loadBaseline();
tick(); setInterval(tick, 1000);
