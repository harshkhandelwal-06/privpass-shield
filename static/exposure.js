// PrivPass Shield — Exposure map (view-exposure). Purely presentational: renders /api/exposure/graph.
(function () {
  const NS = 'http://www.w3.org/2000/svg';
  const C = { x: 400, y: 290 };
  const ICONS = {
    password: 'M14.5 9.5a4.5 4.5 0 1 1-4.5-4.5 4.5 4.5 0 0 1 4.5 4.5zm0 0H21v3.5m-3-3.5v3',
    factors: 'M12 3l7 3v5c0 5-3 8.2-7 10-4-1.8-7-5-7-10V6zm-3 9 2 2 4-4',
    sessions: 'M3 5h18v11H3zM8 20h8M12 16v4',
    vault: 'M6 11h12v9H6zM8.5 11V8a3.5 3.5 0 0 1 7 0v3M12 15v2',
    alerts: 'M6 16v-5a6 6 0 1 1 12 0v5l1.5 2h-15zM10 20.5a2 2 0 0 0 4 0',
    repo: 'M6 4v10M6 20a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM18 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4zM18 8c0 5-12 3-12 8',
    honey: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zm0 4a5 5 0 1 0 0 10 5 5 0 0 0 0-10zm0 4a1 1 0 1 0 0 2 1 1 0 0 0 0-2z',
  };
  const esc = (v) => (typeof escapeHtml === 'function' ? escapeHtml(String(v ?? '')) : String(v ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`));
  const q = (s) => document.querySelector(s);
  const el = (tag, attrs = {}, parent) => { const n = document.createElementNS(NS, tag); Object.entries(attrs).forEach(([k, v]) => n.setAttribute(k, v)); parent?.appendChild(n); return n; };
  const ago = (iso) => {
    const s = (Date.now() - new Date(iso + (iso.endsWith('Z') ? '' : 'Z')).getTime()) / 1000;
    if (s < 60) return 'just now'; if (s < 3600) return `${Math.round(s / 60)} min ago`; if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  };
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches || navigator.webdriver;

  // ---------------------------------------------------------------- actions (fix buttons everywhere on the page)
  async function goFinding(id) {
    nav('secrets');
    for (let i = 0; i < 20; i++) {
      await new Promise((r) => setTimeout(r, 150));
      // Reveal every loaded finding (the list pages 40 at a time) and clear filters so the target is rendered.
      const idx = (state.secretFindings || []).findIndex((f) => f.id === id);
      if (idx >= 0 && !document.querySelector(`[data-finding-id="${CSS.escape(id)}"]`)) {
        ['#finding-search', '#finding-severity', '#finding-status'].forEach((s) => { const x = q(s); if (x) x.value = x.tagName === 'SELECT' ? (x.options[0]?.value ?? '') : ''; });
        state.secretFindingLimit = Math.max(state.secretFindingLimit || 40, idx + 1);
        renderFindings(state.secretFindings, { preserveLimit: true });
      }
      const card = document.querySelector(`[data-finding-id="${CSS.escape(id)}"]`);
      if (card) {
        const d = card.querySelector('details'); if (d) d.open = true;
        card.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'center' });
        card.classList.add('flash'); setTimeout(() => card.classList.remove('flash'), 2200);
        return;
      }
    }
    toast('That finding belongs to an earlier scan; Incident Center lists it with the rest of its repository.');
  }
  function act(action) {
    if (!action) return;
    if (action === 'security') return openSecurity(false);
    if (action.startsWith('nav:')) return nav(action.slice(4));
    if (action.startsWith('finding:')) return goFinding(action.slice(8));
  }

  // ---------------------------------------------------------------- score gauge + factors
  function renderScore(data) {
    const card = q('#xp-score-card'); const ex = data.exposure || { score: 0, label: 'GUARDED', factors: [] };
    card.dataset.level = ex.label;
    q('#xp-map').dataset.level = ex.label;
    const ticks = q('#xp-ticks'); ticks.innerHTML = '';
    for (let i = 0; i <= 10; i++) {
      const a = Math.PI * (1 - i / 10); const r1 = 104, r2 = i % 5 ? 110 : 114;
      el('line', { x1: 110 + r1 * Math.cos(a), y1: 110 - r1 * Math.sin(a), x2: 110 + r2 * Math.cos(a), y2: 110 - r2 * Math.sin(a) }, ticks);
    }
    requestAnimationFrame(() => { q('#xp-arc').style.strokeDashoffset = String(283 * (1 - ex.score / 100)); });
    const num = q('#xp-score'); const target = ex.score; const t0 = performance.now();
    const step = (t) => { const k = Math.min(1, (t - t0) / 1200); num.textContent = Math.round(target * (1 - Math.pow(1 - k, 3))); if (k < 1 && !reduced) requestAnimationFrame(step); else num.textContent = target; };
    requestAnimationFrame(step);
    q('#xp-label').textContent = ex.label;
    q('#xp-caption-extra').textContent = ex.factors.length ? `${ex.factors.length} thing${ex.factors.length > 1 ? 's' : ''} to fix.` : '';
    const box = q('#xp-factors');
    box.innerHTML = ex.factors.filter((f) => f.points > 0).map((f) => `<button class="xp-factor ${esc(f.severity)}" data-act="${esc(f.action)}" type="button"><span class="pts">+${f.points}</span><span><b>${esc(f.label)}</b><small>${esc(f.fix)}</small></span><span class="go">Fix →</span></button>`).join('')
      || '<div class="xp-allclear">✓ Nothing exposed right now. Keep it that way: scan every repository and plant a honeytoken.</div>';
  }

  // ---------------------------------------------------------------- the map
  function nodesFor(data) {
    const id = data.identity; const pw = id.password || {};
    const inner = [
      { key: 'password', icon: 'password', label: 'Password', sub: id.breached ? 'BREACHED' : pw.score != null ? `score ${pw.score}` : 'set',
        state: id.breached ? 'critical' : pw.score != null && pw.score < 60 ? 'warn' : 'safe', action: 'security', actionLabel: id.breached ? 'Change password' : 'Security settings',
        title: id.breached ? 'Your password is in breach data' : 'Password',
        facts: [['Status', id.breached ? 'found in a breach' : 'not found in breaches'], ['Strength at last change', pw.score != null ? `${pw.score}/100 (${pw.label || '—'})` : 'unknown'], ['Last set', ago(pw.set_at)], ['Last sign-in check', pw.last_check || 'not yet']] },
      { key: 'factors', icon: 'factors', label: 'Sign-in factors', sub: id.passkeys ? `${id.passkeys} passkey${id.passkeys > 1 ? 's' : ''}` : id.mfa ? 'MFA on' : 'password only',
        state: id.passkeys || id.mfa ? 'safe' : 'warn', action: 'security', actionLabel: id.passkeys ? 'Manage passkeys' : 'Add a passkey',
        title: id.passkeys || id.mfa ? 'More than a password protects you' : 'The password is your only factor',
        facts: [['Passkeys', id.passkeys], ['Authenticator MFA', id.mfa ? 'on' : 'off'], ['Phishing-resistant', id.passkeys ? 'yes' : 'no']] },
      { key: 'sessions', icon: 'sessions', label: 'Sessions', sub: `${id.sessions} active`, state: id.sessions > 3 ? 'warn' : 'safe', action: 'security', actionLabel: 'Review',
        title: `${id.sessions} signed-in session${id.sessions === 1 ? '' : 's'}`, facts: [['Active now', id.sessions], ['Expire after', '60 min idle'], ['Stolen-cookie risk', id.sessions > 3 ? 'raised' : 'low']] },
      { key: 'vault', icon: 'vault', label: 'Vault', sub: id.vault_items ? `${id.vault_items} items` : 'empty', state: id.vault_items ? 'safe' : 'idle', action: 'nav:vault', actionLabel: 'Open vault',
        title: 'Zero-knowledge vault', facts: [['Encrypted items', id.vault_items], ['Encryption', 'AES-256-GCM in your browser'], ['Readable by the server', 'no']] },
      { key: 'alerts', icon: 'alerts', label: 'Alerts', sub: data.alerts_unread ? `${data.alerts_unread} unread` : 'all read', state: data.alerts_unread ? 'warn' : 'safe', action: 'bell', actionLabel: 'Open alerts',
        title: 'Your alerts', facts: [['Unread', data.alerts_unread]] },
    ];
    const outer = (data.repos || []).map((r) => ({
      key: `repo:${r.name}`, icon: 'repo', label: r.name.length > 18 ? `${r.name.slice(0, 17)}…` : r.name, sub: r.open ? `${r.open} open` : 'clean', state: r.state, repo: r.name,
      action: 'nav:secrets', actionLabel: 'Open findings', title: r.name,
      facts: [['Open findings', r.open], ['Critical / high', `${r.severity.CRITICAL} / ${r.severity.HIGH}`], ['Only in git history', r.history_only], ['Files scanned', r.files], ['Scanned', ago(r.scanned_at)]] }));
    const h = data.honeytokens || { count: 0 };
    outer.push({ key: 'honey', icon: 'honey', label: 'Honeytokens', sub: h.tripped ? `${h.tripped} TRIPPED` : h.count ? `${h.count} armed` : 'none planted',
      state: h.tripped ? 'critical' : h.count ? 'safe' : 'idle', action: 'nav:secrets', actionLabel: h.count ? 'View bait keys' : 'Plant one',
      title: h.tripped ? 'Someone used one of your bait keys' : 'Bait keys (tripwires)', facts: [['Planted', h.count], ['Tripped', h.tripped], ['Total uses', h.trips]] });
    if (!(data.repos || []).length) outer.unshift({ key: 'norepo', icon: 'repo', label: 'No repository', sub: 'scan one', state: 'idle', action: 'nav:secrets', actionLabel: 'Scan a repository', title: 'No repository scanned yet', facts: [['Why it matters', 'leaked keys are the #1 cloud breach cause']] });
    const place = (list, rx, ry, offset) => list.forEach((n, i) => { const a = offset + (2 * Math.PI * i) / list.length; n.x = C.x + rx * Math.cos(a); n.y = C.y + ry * Math.sin(a); n.angle = a; });
    const compact = isCompact();
    if (compact) all(inner, outer).forEach((n) => { if (n.label.length > 13) n.label = `${n.label.slice(0, 12)}…`; });
    place(inner, compact ? 120 : 168, compact ? 120 : 128, -Math.PI / 2);
    place(outer, compact ? 228 : 322, compact ? 232 : 222, -Math.PI / 2 + Math.PI / Math.max(2, outer.length));
    return { inner, outer };
  }

  const all = (a, b) => [...a, ...b];
  const isCompact = () => (q('#xp-map')?.clientWidth || 900) < 620;
  let pinned = null; let lastData = null; let lastCompact = null;
  addEventListener('resize', () => { clearTimeout(window.__xpR); window.__xpR = setTimeout(() => { if (lastData && isCompact() !== lastCompact && q('#view-exposure.active')) renderMap(lastData); }, 200); });
  function renderMap(data) {
    const svg = q('#xp-svg'); svg.innerHTML = ''; svg.classList.remove('focus'); pinned = null; lastData = data;
    const compact = lastCompact = isCompact();
    svg.setAttribute('viewBox', compact ? '85 0 630 600' : '0 0 800 600'); svg.classList.toggle('compact', compact);
    const { inner, outer } = nodesFor(data);
    const all = [...inner, ...outer];
    el('ellipse', { class: 'xp-orbit', cx: C.x, cy: C.y, rx: compact ? 120 : 168, ry: compact ? 120 : 128 }, svg);
    el('ellipse', { class: 'xp-orbit o2', cx: C.x, cy: C.y, rx: compact ? 228 : 322, ry: compact ? 232 : 222 }, svg);
    const edges = el('g', {}, svg); const flows = el('g', {}, svg); const dots = el('g', {}, svg); const nodesG = el('g', {}, svg);
    all.forEach((n, i) => {
      const mx = (n.x + C.x) / 2, my = (n.y + C.y) / 2; const dx = C.x - n.x, dy = C.y - n.y; const len = Math.hypot(dx, dy) || 1;
      const bend = 0.12 * len * (i % 2 ? 1 : -1);
      const d = `M${n.x.toFixed(1)} ${n.y.toFixed(1)} Q${(mx - (dy / len) * bend).toFixed(1)} ${(my + (dx / len) * bend).toFixed(1)} ${C.x} ${C.y}`;
      const e = el('path', { d, class: `xp-edge ${n.state}${reduced ? '' : ' draw'}`, 'data-key': n.key }, edges);
      if (!reduced) { const L = e.getTotalLength?.() || len; e.style.setProperty('--len', L); e.style.animationDelay = `${0.15 + i * 0.05}s`; }
      if (n.state === 'critical' || n.state === 'warn') el('path', { d, class: `xp-flow ${n.state}`, 'data-key': n.key }, flows);
      n.edge = e;
    });
    // open findings orbit their repository as small severity-coloured satellites
    outer.filter((n) => n.repo).forEach((n) => {
      const list = (data.open_findings || []).filter((f) => f.repo === n.repo).slice(0, 9);
      list.forEach((f, k) => {
        // fan the dots out sideways (away from the centre line) so they never cover the node's label
        const side = n.x < C.x - 5 ? Math.PI : 0;
        const labelBelow = n.y >= C.y - 10;
        const tilt = (labelBelow ? -0.75 : 0.75) * (side === 0 ? 1 : -1);   // lean away from the label
        const a = side + tilt + (k - (list.length - 1) / 2) * 0.3; const r = 44;
        const dot = el('circle', { cx: n.x + r * Math.cos(a), cy: n.y + r * Math.sin(a), r: f.severity === 'CRITICAL' ? 6 : 5, class: `xp-dot ${f.severity}` }, dots);
        const t = el('title', {}, dot); t.textContent = `${f.severity} · ${f.type} · ${f.file}:${f.line}`;
      });
    });
    // identity core
    const core = el('g', { class: 'xp-core' }, nodesG);
    el('circle', { class: 'core-ring', cx: C.x, cy: C.y, r: 48 }, core); el('circle', { class: 'core-ring r2', cx: C.x, cy: C.y, r: 48 }, core);
    el('circle', { class: 'core-disc', cx: C.x, cy: C.y, r: 48 }, core);
    const init = el('text', { class: 'core-init', x: C.x, y: C.y + 12 }, core); init.textContent = (data.identity.email || '?')[0].toUpperCase();
    const mail = el('text', { class: 'core-mail', x: C.x, y: C.y + 70 }, core); mail.textContent = data.identity.email;
    all.forEach((n, i) => {
      const g = el('g', { class: `xp-node ${n.state}`, tabindex: '0', role: 'button', 'aria-label': `${n.label}: ${n.sub}`, 'data-key': n.key }, nodesG);
      g.style.animationDelay = reduced ? '0s' : `${0.25 + i * 0.07}s`;
      el('circle', { class: 'halo', cx: n.x, cy: n.y, r: 30 }, g);
      el('circle', { class: 'disc', cx: n.x, cy: n.y, r: 26 }, g);
      el('path', { class: 'ico', d: ICONS[n.icon], transform: `translate(${n.x - 12} ${n.y - 12})` }, g);
      const below = n.y >= C.y - 10;
      const t1 = el('text', { x: n.x, y: below ? n.y + 46 : n.y - 50 }, g); t1.textContent = n.label;
      const t2 = el('text', { class: 'sub', x: n.x, y: below ? n.y + 61 : n.y - 36 }, g); t2.textContent = n.sub.toUpperCase();
      const show = () => showDetail(n, svg);
      g.addEventListener('mouseenter', () => { if (!pinned) show(); });
      g.addEventListener('focus', show);
      g.addEventListener('click', (ev) => { ev.stopPropagation(); pinned = pinned === n.key ? null : n.key; show(); if (!pinned) clearFocus(svg); });
      g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); act(n.action === 'bell' ? null : n.action); if (n.action === 'bell') q('#bell-btn')?.click(); } });
      n.g = g;
    });
    svg.addEventListener('mouseleave', () => { if (!pinned) clearFocus(svg); });
    svg.addEventListener('click', () => { pinned = null; clearFocus(svg); });
    // default: show the riskiest node
    const worst = all.find((n) => n.state === 'critical') || all.find((n) => n.state === 'warn');
    if (worst) showDetail(worst, null); else emptyDetail();
  }
  function clearFocus(svg) { svg.classList.remove('focus'); svg.querySelectorAll('.sel').forEach((x) => x.classList.remove('sel')); }
  function emptyDetail() { q('#xp-detail').innerHTML = '<div class="xp-detail-empty"><b>Select any node</b><span>Hover or tap a node to see what it exposes and how to close it.</span></div>'; }
  function showDetail(n, svg) {
    if (svg) {
      clearFocus(svg); svg.classList.add('focus');
      svg.querySelectorAll(`[data-key="${CSS.escape(n.key)}"]`).forEach((x) => x.classList.add('sel'));
      svg.querySelector('.xp-core')?.classList.add('sel');
    }
    const stateText = { safe: 'PROTECTED', warn: 'WEAK', critical: 'EXPOSED', idle: 'NOT SET UP' }[n.state] || n.state;
    q('#xp-detail').innerHTML = `<div class="xp-detail-grid"><div><h4>${esc(n.title)} <span class="xp-state ${esc(n.state)}">${stateText}</span></h4>
      <ul>${n.facts.map(([k, v]) => `<li>${esc(k)}: <b>${esc(v)}</b></li>`).join('')}</ul></div>
      <button class="btn ${n.state === 'critical' || n.state === 'warn' ? 'primary' : 'secondary'}" type="button" id="xp-detail-act">${esc(n.actionLabel)} →</button></div>`;
    q('#xp-detail-act').addEventListener('click', () => { if (n.action === 'bell') { q('#bell-btn')?.click(); } else act(n.action); });
  }

  // ---------------------------------------------------------------- attack paths, controls, timeline
  function renderPaths(data) {
    const box = q('#xp-paths'); const paths = data.paths || [];
    if (!paths.length) { box.innerHTML = '<div class="xp-allclear">✓ No open attack paths. Every entry point we can see is closed.</div>'; return; }
    box.innerHTML = paths.map((p, i) => `<div class="xp-path ${esc(p.severity)}"><span class="rank">${String(i + 1).padStart(2, '0')}</span>
      <div class="xp-step"><small>Entry point</small><b>${esc(p.entry)}</b><span>${esc(p.where)}</span></div><i class="xp-arrow"></i>
      <div class="xp-step"><small>How it's used</small><b>${esc(p.pivot)}</b></div><i class="xp-arrow"></i>
      <div class="xp-step"><small>Impact</small><b>${esc(p.impact)}</b><span>Fix: ${esc(p.fix)}</span></div>
      <button class="btn ${p.severity === 'critical' ? 'primary' : 'secondary'} fix" type="button" data-act="${esc(p.action)}">Fix →</button></div>`).join('');
    box.querySelectorAll('.xp-path').forEach((row, i) => setTimeout(() => row.classList.add('in'), reduced ? 0 : 120 + i * 110));
  }
  function renderControls(data) {
    const list = data.controls || []; const ok = list.filter((c) => c.ok).length;
    q('#xp-ring-num').textContent = `${ok}/${list.length}`;
    requestAnimationFrame(() => { q('#xp-ring').style.strokeDashoffset = String(314 * (1 - (list.length ? ok / list.length : 0))); });
    q('#xp-controls').innerHTML = list.map((c) => `<li class="${c.ok ? 'ok' : 'todo'}"><button type="button" data-act="${esc(c.action)}"><span class="tick">✓</span>${esc(c.label)}${c.ok ? '' : '<span class="go">Fix →</span>'}</button></li>`).join('');
  }
  const EVENT_TEXT = {
    LOGIN_SUCCESS: (d) => `Signed in${d.method ? ` with ${d.method}` : ''}`, LOGOUT: () => 'Signed out', ACCOUNT_CREATED: () => 'Account created (breach gate passed)',
    REPOSITORY_SCAN: (d) => `Scanned a repository: ${d.findings ?? 0} findings${d.history_only ? `, ${d.history_only} only in history` : ''}`,
    GITHUB_REPO_SCAN: (d) => `Scanned a GitHub repository: ${d.findings ?? 0} findings`, FINDING_TRANSITION: (d) => `Moved a finding ${d.from || ''} → ${d.status || ''}`,
    PASSWORD_CHANGED: () => 'Changed password (vault re-encrypted)', PASSWORD_BREACHED_SINCE_SET: () => 'Password found in a new breach',
    PASSKEY_ADDED: () => 'Added a passkey', PASSKEY_REMOVED: () => 'Removed a passkey', HONEYTOKEN_CREATED: (d) => `Planted a honeytoken${d.label ? ` “${d.label}”` : ''}`,
    HONEYTOKEN_TRIPPED: (d) => `Honeytoken used${d.ip ? ` from ${d.ip}` : ''}`, MFA_ENABLED: () => 'Turned on MFA', LOGIN_FAILED: () => 'Failed sign-in attempt',
    AI_INCIDENT_REPORT: () => 'Generated an incident report', ACCOUNT_BREACH_AUDIT: () => 'Ran a test-account breach audit',
  };
  const GOOD = new Set(['PASSWORD_CHANGED', 'PASSKEY_ADDED', 'MFA_ENABLED', 'ACCOUNT_CREATED', 'HONEYTOKEN_CREATED']);
  function renderTimeline(data) {
    const items = data.timeline || [];
    q('#xp-timeline').innerHTML = items.length ? items.map((e) => `<li class="${esc(e.severity)}${GOOD.has(e.event) ? ' good' : ''}"><b>${esc((EVENT_TEXT[e.event] || (() => e.event.toLowerCase().replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())))(e.detail || {}))}</b><small>${esc(ago(e.at))}</small></li>`).join('')
      : '<li class="empty-state">No activity yet.</li>';
  }

  document.addEventListener('click', (e) => { const b = e.target.closest?.('#view-exposure [data-act]'); if (b) act(b.dataset.act); });

  window.loadExposureGraph = async function loadExposureGraph() {
    const meta = q('#graph-live-meta');
    try {
      const data = await api('/api/exposure/graph');
      const open = (data.open_findings || []).length;
      if (meta) meta.textContent = `${data.identity.workspace === 'demo' ? 'Demo' : 'Live'} workspace · ${(data.repos || []).length} repositor${(data.repos || []).length === 1 ? 'y' : 'ies'} · ${open} open finding${open === 1 ? '' : 's'}`;
      renderScore(data); renderMap(data); renderPaths(data); renderControls(data); renderTimeline(data);
    } catch (error) {
      if (meta) meta.textContent = 'Sign in to map your exposure.';
      q('#xp-svg').innerHTML = ''; emptyDetail();
      q('#xp-factors').innerHTML = '<div class="empty-state">Sign in to see what drives your score.</div>';
      q('#xp-paths').innerHTML = '<div class="empty-state">Sign in to see your attack paths.</div>';
    }
  };
})();
