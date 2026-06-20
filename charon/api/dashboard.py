"""Phase 6 dashboard — a single self-contained page (no build step, no external
JS) served at GET /. It reads the control-plane's own JSON endpoints (/agents,
/delegations, /audit, /reaper/run) and renders the inventory, lifecycle state
counts, the delegation graph, a reaper dry-run preview, and the audit feed."""

DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Charon — NHI Lifecycle Engine</title>
<style>
  :root { --bg:#0f1115; --panel:#171a21; --line:#262b36; --fg:#e6e9ef;
          --muted:#8b93a7; --accent:#6ea8fe; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  header { padding:16px 24px; border-bottom:1px solid var(--line); display:flex;
           align-items:baseline; gap:12px; }
  header h1 { font-size:18px; margin:0; }
  header .sub { color:var(--muted); font-size:13px; }
  main { padding:24px; display:grid; gap:24px; grid-template-columns:1fr 1fr; }
  .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px;
           padding:16px; }
  .panel.full { grid-column:1 / -1; }
  h2 { font-size:14px; margin:0 0 12px; color:var(--muted); text-transform:uppercase;
       letter-spacing:.05em; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line);
          font-size:13px; vertical-align:top; }
  th { color:var(--muted); font-weight:600; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; }
  .badge { display:inline-block; padding:1px 8px; border-radius:999px; font-size:11px;
           font-weight:600; }
  .PROVISIONED{background:#3a3f4b;color:#cfd6e4;}
  .ACTIVE{background:#13351f;color:#5fd28a;}
  .IDLE{background:#3a341a;color:#e2c55b;}
  .REVOKED{background:#3a1f1f;color:#f08a8a;}
  .DECOMMISSIONED{background:#262b36;color:#8b93a7;}
  .counts span { margin-right:14px; }
  button { background:var(--accent); color:#0b0d11; border:0; border-radius:8px;
           padding:8px 14px; font-weight:600; cursor:pointer; }
  .muted { color:var(--muted); }
  .feed { max-height:280px; overflow:auto; font-size:12.5px; }
  .feed div { padding:3px 0; border-bottom:1px solid var(--line); }
  svg { width:100%; height:340px; background:#0b0d11; border-radius:8px; }
  .node rect { fill:#1d2230; stroke:#39414f; rx:6; }
  .node.principal rect { stroke:var(--accent); }
  .node text { fill:var(--fg); font-size:11px; }
  .edge { stroke:#4a5366; stroke-width:1.5; marker-end:url(#arrow); }
</style>
</head>
<body>
<header>
  <h1>Charon</h1>
  <span class="sub">NHI Lifecycle Engine — control plane dashboard</span>
  <span class="sub" id="audit-status"></span>
</header>
<main>
  <section class="panel full">
    <h2>Lifecycle</h2>
    <div class="counts" id="counts"></div>
  </section>

  <section class="panel">
    <h2>Identity inventory</h2>
    <table><thead><tr>
      <th>Name</th><th>State</th><th>Owner</th><th>Scopes</th><th>Last seen</th>
    </tr></thead><tbody id="agents"></tbody></table>
  </section>

  <section class="panel">
    <h2>Reaper preview <span class="muted">(dry run)</span></h2>
    <p><button onclick="runReaper()">Run reaper preview</button></p>
    <table><thead><tr><th>Agent</th><th>Action</th><th>Detail</th></tr></thead>
      <tbody id="reaper"></tbody></table>
  </section>

  <section class="panel full">
    <h2>Delegation graph <span class="muted">(provenance: principal &rarr; agents)</span></h2>
    <svg id="graph" viewBox="0 0 1000 340" preserveAspectRatio="xMinYMin meet">
      <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3"
        orient="auto"><path d="M0,0 L7,3 L0,6 z" fill="#4a5366"/></marker></defs>
    </svg>
  </section>

  <section class="panel full">
    <h2>Audit feed</h2>
    <div class="feed" id="feed"></div>
  </section>
</main>

<script>
const short = s => (s||"").length > 28 ? s.slice(0,12)+"\u2026"+s.slice(-10) : s;

async function getJSON(u, opts){ const r = await fetch(u, opts); return r.json(); }

async function load(){
  const agents = await getJSON('/agents');
  const dels   = await getJSON('/delegations');
  const audit  = await getJSON('/audit');

  // lifecycle counts
  const counts = {};
  agents.forEach(a => counts[a.state] = (counts[a.state]||0)+1);
  document.getElementById('counts').innerHTML =
    Object.entries(counts).map(([s,n]) =>
      `<span><span class="badge ${s}">${s}</span> ${n}</span>`).join('') || '<span class="muted">no identities yet</span>';

  // inventory
  document.getElementById('agents').innerHTML = agents.map(a => `
    <tr>
      <td>${a.name}<br><code class="muted">${short(a.spiffe_id)}</code></td>
      <td><span class="badge ${a.state}">${a.state}</span></td>
      <td>${a.owner}</td>
      <td><code>${(a.scopes||[]).join(' ')||'\u2014'}</code></td>
      <td class="muted">${a.last_seen ? new Date(a.last_seen*1000).toLocaleString() : 'never'}</td>
    </tr>`).join('');

  // audit
  const st = document.getElementById('audit-status');
  st.textContent = audit.intact ? '\u2713 audit chain intact' : '\u26a0 audit chain BROKEN';
  st.style.color = audit.intact ? '#5fd28a' : '#f08a8a';
  document.getElementById('feed').innerHTML = audit.entries.slice().reverse().map(e =>
    `<div><code class="muted">#${e.seq}</code> <b>${e.event}</b> `
    + `<code>${short(e.subject)}</code> `
    + `<span class="muted">${JSON.stringify(e.details)}</span></div>`).join('');

  drawGraph(dels);
}

function drawGraph(edges){
  const svg = document.getElementById('graph');
  // clear all but <defs>
  [...svg.querySelectorAll('.node,.edge')].forEach(n => n.remove());
  if(!edges.length){
    svg.insertAdjacentHTML('beforeend',
      '<text x="16" y="28" fill="#8b93a7" font-size="12">no delegations recorded yet</text>');
    return;
  }
  // assign depth: a node that is never a delegate sits at depth 0 (the principal)
  const nodes = new Set(), isDelegate = new Set();
  edges.forEach(e => { nodes.add(e.delegator); nodes.add(e.delegate); isDelegate.add(e.delegate); });
  const depth = {};
  const adj = {};
  edges.forEach(e => { (adj[e.delegator] = adj[e.delegator]||[]).push(e.delegate); });
  [...nodes].filter(n => !isDelegate.has(n)).forEach(r => bfs(r, 0));
  function bfs(n, d){ if(depth[n]!==undefined && depth[n]>=d) return; depth[n]=d;
    (adj[n]||[]).forEach(m => bfs(m, d+1)); }
  [...nodes].forEach(n => { if(depth[n]===undefined) depth[n]=0; });

  const byDepth = {};
  [...nodes].forEach(n => { (byDepth[depth[n]] = byDepth[depth[n]]||[]).push(n); });
  const pos = {}; const W=200, H=70;
  Object.entries(byDepth).forEach(([d, ns]) => ns.forEach((n,i) =>
    pos[n] = { x: 30 + d*W, y: 30 + i*H }));

  edges.forEach(e => {
    const a = pos[e.delegator], b = pos[e.delegate];
    if(!a||!b) return;
    svg.insertAdjacentHTML('beforeend',
      `<line class="edge" x1="${a.x+150}" y1="${a.y+18}" x2="${b.x}" y2="${b.y+18}"/>`);
  });
  [...nodes].forEach(n => {
    const p = pos[n]; const principal = !isDelegate.has(n);
    svg.insertAdjacentHTML('beforeend',
      `<g class="node ${principal?'principal':''}">
         <rect x="${p.x}" y="${p.y}" width="150" height="36"/>
         <text x="${p.x+10}" y="${p.y+22}">${short(n)}</text>
       </g>`);
  });
}

async function runReaper(){
  const res = await getJSON('/reaper/run', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({apply:false})
  });
  document.getElementById('reaper').innerHTML = res.actions.length
    ? res.actions.map(a => `<tr><td>${a.name}</td><td><b>${a.action}</b></td>
        <td class="muted">${a.detail}</td></tr>`).join('')
    : '<tr><td colspan="3" class="muted">nothing to reap</td></tr>';
}

load();
</script>
</body>
</html>
"""
