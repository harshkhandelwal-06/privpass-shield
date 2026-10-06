// PrivPass Shield platform features. Loaded after app.js (shares its globals: state, api, $, $$, toast…).

// ---------------------------------------------------------------- offline breach corpus (Bloom filter)
window.PrivPassBloom = (() => {
  let loading = null;
  function load() {
    if (!loading) {
      loading = Promise.all([
        fetch('/static/breach/top1m.json').then((r) => { if (!r.ok) throw new Error('corpus unavailable'); return r.json(); }),
        fetch('/static/breach/top1m.bloom').then((r) => { if (!r.ok) throw new Error('corpus unavailable'); return r.arrayBuffer(); }),
      ]).then(([meta, buf]) => ({ meta, bits: new Uint8Array(buf) })).catch((e) => { loading = null; throw e; });
    }
    return loading;
  }
  // SHA-1(NFKC(password)) -> Kirsch-Mitzenmacher double hashing, identical to tools/build_breach_bloom.py.
  async function check(password) {
    const { meta, bits } = await load();
    const d = new DataView(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(String(password).normalize('NFKC'))));
    const h1 = d.getUint32(0); const h2 = (d.getUint32(4) | 1) >>> 0;
    for (let i = 0; i < meta.k; i++) {
      const idx = (h1 + i * h2) % meta.m;
      if (!(bits[idx >> 3] & (1 << (idx & 7)))) return false;
    }
    return true;
  }
  return { load, check };
})();
// Warm the corpus after first paint so checks are instant later.
setTimeout(() => window.PrivPassBloom.load().catch(() => {}), 1500);

// ---------------------------------------------------------------- deadlines (SLA)
function fmtHours(h) {
  if (h == null) return '—';
  const a = Math.abs(h);
  return a >= 48 ? `${(a / 24).toFixed(1)} d` : a >= 1 ? `${a.toFixed(1)} h` : `${Math.round(a * 60)} min`;
}
function slaChip(sla, status) {
  if (!sla) return '';
  if (sla.state === 'met') return '<span class="finding-chip sla met">✓ FIXED IN TIME</span>';
  if (sla.state === 'missed') return '<span class="finding-chip sla missed">FIXED LATE</span>';
  if (sla.state === 'overdue') return `<span class="finding-chip sla overdue">⏱ OVERDUE ${fmtHours(sla.remaining_hours)}</span>`;
  return `<span class="finding-chip sla ${sla.state}">⏱ ${fmtHours(sla.remaining_hours)} LEFT</span>`;
}
function slaText(sla) {
  if (!sla) return '';
  const t = { met: 'Rotated within deadline', missed: 'Rotated after deadline', overdue: `Overdue by ${fmtHours(sla.remaining_hours)}`, at_risk: `${fmtHours(sla.remaining_hours)} left to rotate`, on_track: `${fmtHours(sla.remaining_hours)} left to rotate` }[sla.state];
  return `<small class="sla-line ${sla.state}">⏱ ${t} (deadline ${sla.sla_hours} h)</small>`;
}
function renderSla(ov) {
  const s = ov.sla || {};
  setText('sla-contain', fmtHours(s.mean_hours_to_contain));
  setText('sla-rotate', fmtHours(s.mean_hours_to_rotate));
  setText('sla-compliance', s.sla_compliance_percent == null ? '—' : `${s.sla_compliance_percent}%`);
  setText('sla-overdue', s.overdue ?? '—');
  setText('sla-atrisk', `${s.at_risk ?? 0} at risk of missing the deadline`);
  setText('honey-trips', ov.honeytoken_trips ?? 0);
  $('#sla-overdue')?.classList.toggle('bad', (s.overdue || 0) > 0);
  $('#honey-trips')?.classList.toggle('bad', (ov.honeytoken_trips || 0) > 0);
}

// ---------------------------------------------------------------- notifications bell
let bellTimer = null;
async function loadBell() {
  if (!state.auth) return;
  try {
    const n = await api('/api/notifications');
    const count = $('#bell-count'); count.textContent = n.unread; count.classList.toggle('hidden', !n.unread);
    $('#bell-list').innerHTML = n.items.length ? n.items.map((i) => `<div class="bell-item ${i.read ? '' : 'unread'} sev-${escapeHtml(i.severity)}" data-link="${escapeHtml(i.link)}">
      <b>${escapeHtml(i.title)}</b><span>${escapeHtml(i.body)}</span><small>${new Date(i.created_at + 'Z').toLocaleString()}</small></div>`).join('') : '<div class="empty-state">No alerts yet.</div>';
    $$('.bell-item').forEach((el) => el.addEventListener('click', () => { const l = el.dataset.link; $('#bell').classList.remove('open'); if (l === 'account') openSecurity(false); else if (l) nav(l); }));
  } catch {}
}
function startBell() { clearInterval(bellTimer); $('#bell')?.classList.toggle('hidden', !state.auth); if (state.auth) { loadBell(); bellTimer = setInterval(loadBell, 15000); } }
$('#bell-btn')?.addEventListener('click', (e) => {
  e.stopPropagation();
  const open = !$('#bell').classList.contains('open');
  $('#bell').classList.toggle('open', open); $('#bell-btn').setAttribute('aria-expanded', String(open));
  if (open) { toggleAccountMenu(false); loadBell(); }
});
document.addEventListener('click', (e) => { if (!e.target.closest?.('#bell')) $('#bell')?.classList.remove('open'); });
$('#bell-read')?.addEventListener('click', async () => { try { await api('/api/notifications/read-all', { method: 'POST', body: '{}' }); loadBell(); } catch {} });
const _updateAuthUI = updateAuthUI;
updateAuthUI = function () { _updateAuthUI(); startBell(); };  // eslint-disable-line no-func-assign

// ---------------------------------------------------------------- honeytokens
state.honeyRaw = {};
async function loadHoneytokens() {
  const list = $('#honey-list'); if (!list) return;
  if (!state.auth) { list.innerHTML = '<div class="empty-state">Sign in to create honeytokens.</div>'; return; }
  try {
    const rows = await api('/api/honeytokens');
    list.innerHTML = rows.length ? rows.map((h) => `<div class="honey-row ${h.trips ? 'tripped' : ''}">
      <div><b>${escapeHtml(h.label)}</b><span>${h.kind === 'url' ? 'Canary URL' : 'Fake API key'} · <code>${escapeHtml(h.preview)}</code></span>
      ${h.trips ? `<small class="bad">🚨 Tripped ${h.trips}× — last from ${escapeHtml(h.recent[0]?.ip || '?')} (${escapeHtml((h.recent[0]?.user_agent || '').slice(0, 40))})</small>` : '<small>Armed · never used</small>'}</div>
      <div class="honey-actions">${state.honeyRaw[h.id] ? `<button class="mini-action honey-test" data-id="${h.id}">Simulate attacker</button>` : ''}<button class="mini-action honey-del" data-id="${h.id}">Remove</button></div></div>`).join('')
      : '<div class="empty-state">No honeytokens yet.</div>';
    $$('.honey-test').forEach((b) => b.addEventListener('click', () => tripHoneytoken(b.dataset.id)));
    $$('.honey-del').forEach((b) => b.addEventListener('click', async () => { await api(`/api/honeytokens/${b.dataset.id}`, { method: 'DELETE', body: '{}' }); loadHoneytokens(); }));
  } catch (e) { list.innerHTML = `<div class="empty-state">${escapeHtml(e.message)}</div>`; }
}
$('#honey-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.auth) { openAuth('signin'); return; }
  try {
    const r = await api('/api/honeytokens', { method: 'POST', body: JSON.stringify({ label: $('#honey-label').value.trim() || 'Bait key', kind: $('#honey-kind').value }) });
    state.honeyRaw[r.id] = { token: r.token, kind: r.kind };
    const box = $('#honey-new'); box.classList.remove('hidden');
    box.innerHTML = `<div class="detail-label">PLANT THIS (shown once — only its HMAC is stored)</div><pre class="cmd">${escapeHtml(r.snippet)}</pre><button class="mini-action" id="honey-copy">Copy snippet</button>`;
    $('#honey-copy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(r.snippet); toast('Snippet copied — commit it somewhere an attacker would look.'); } catch {} });
    $('#honey-label').value = '';
    loadHoneytokens();
  } catch (err) { toast(err.message); }
});
async function tripHoneytoken(id) {
  const t = state.honeyRaw[id]; if (!t) return;
  // Exactly what an attacker with the leaked config would do:
  const res = t.kind === 'url' ? await fetch(`/c/${t.token}`) : await fetch('/api/canary/v1/charges', { method: 'POST', headers: { Authorization: `Bearer ${t.token}`, 'Content-Type': 'application/json' }, body: '{"amount":5000}' });
  toast(`Attacker got HTTP ${res.status} (a boring error) — and you just got a CRITICAL alert.`);
  setTimeout(() => { loadHoneytokens(); loadBell(); }, 400);
}

// ---------------------------------------------------------------- GitHub scan + fix PR
$('#gh-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!state.auth) { openAuth('signin'); return; }
  const url = $('#gh-url').value.trim(); const btn = $('#gh-scan');
  setBusy(btn, true, 'Cloning…'); setText('gh-status', 'Cloning with full history (hardened git) and scanning every commit…');
  try {
    const data = await api('/api/scans/github', { method: 'POST', body: JSON.stringify({ url }) });
    state.lastScanSource = data.source_url; state.secretFindingLimit = 40;
    renderFindings(data.findings || []);
    setText('gh-status', `${data.findings.length} findings in ${data.files} files${data.history_only ? ` · ${data.history_only} only in history` : ''}. Expand a finding → AI fix → open a fix PR.`);
    loadExposureGraph(); loadIncidents();
  } catch (err) { setText('gh-status', err.message); }
  finally { setBusy(btn, false); }
});
async function openFixPr(id, btn, box) {
  setBusy(btn, true, 'Opening PR…');
  try {
    const r = await api(`/api/github/fix-pr/${encodeURIComponent(id)}`, { method: 'POST', body: '{}' });
    box.innerHTML = `<div class="auth-status show good">Pull request opened: <a href="${escapeHtml(r.pr_url)}" rel="noopener" target="_blank">${escapeHtml(r.pr_url)}</a></div>`;
  } catch (err) { box.innerHTML = `<div class="auth-status show bad">${escapeHtml(err.message)}</div>`; }
  finally { setBusy(btn, false); }
}
function storeRotatedInVault(provider, input) {
  nav('vault');
  if (!state.vaultKey) { toast('Unlock your vault, then press the button again to save the rotated key.'); return; }
  openVaultEditor();
  $('#vault-site').value = `${provider} (rotated key)`;
  $('#vault-username').value = input?.file ? `used by ${input.file}` : '';
  $('#vault-tags').value = 'rotated-secret, secretguard';
  $('#vault-notes').value = `Replacement for the ${input?.type || 'credential'} leaked at ${input?.file}:${input?.line}. Paste the NEW value above; never paste the old one.`;
  $('#vault-password').focus();
  toast('Paste the new key into the password field — it is encrypted in your browser before it is saved.');
}

// ---------------------------------------------------------------- security settings: change password + passkeys
let securityForced = false;
function openSecurity(forced = false) {
  if (!state.auth) { openAuth('signin'); return; }
  securityForced = forced || !!state.auth.must_change_password;
  $('#sec-forced').classList.toggle('hidden', !securityForced);
  api('/api/auth/me').then((me) => {
    const sim = me.breach_flag_source === 'simulation';
    $('#sec-sim-note')?.classList.toggle('hidden', !sim);
    $('#sec-sim-clear')?.classList.toggle('hidden', !(sim && me.role === 'admin'));
  }).catch(() => {});
  const demoAcct = state.auth?.workspace === 'demo';
  $('#sec-demo-note')?.classList.toggle('hidden', !demoAcct);
  $('#sec-change-section')?.classList.toggle('hidden', demoAcct);
  $('#security-close').classList.toggle('hidden', securityForced);
  $('#security-modal').classList.add('open');
  toggleAccountMenu(false);
  loadPasskeys();
}
function closeSecurity() { if (securityForced) return; $('#security-modal').classList.remove('open'); ['sec-current', 'sec-new', 'sec-confirm'].forEach((id) => { $('#' + id).value = ''; }); }
$('#open-security')?.addEventListener('click', () => openSecurity(false));
$('#sec-demo-signup')?.addEventListener('click', async () => {
  securityForced = false; $('#security-modal').classList.remove('open');
  if (typeof signOut === 'function') await signOut('Signed out of the demo account. Create your own account below.');
  openAuth('signup');
});
$('#security-close')?.addEventListener('click', closeSecurity);
$('#security-modal')?.addEventListener('click', (e) => { if (e.target.id === 'security-modal') closeSecurity(); });
['sec-new', 'sec-confirm'].forEach((id) => $('#' + id)?.addEventListener('input', () => updatePolicyList('sec')));

// ---------------------------------------------------------------- 7.3 breach lock: the server locked this account
function showBreachLock(detail, email) {
  const wasSignedIn = !!state.auth;
  if (state.auth) { state.auth = null; try { lockVault(true); } catch {} updateAuthUI(); }
  $('#security-modal')?.classList.remove('open');
  const demo = /simulation on a shared demo account/i.test(detail);
  setText('lock-email', email || 'this account');
  setText('lock-reason', demo ? 'An admin simulated a new breach on this shared demo account. The demo admin can remove it in Command Center → Remove simulation data.'
    : 'Your password was just found in breach data. To protect you, every session was signed out and the account is locked. Choose a new password to unlock it.');
  $('#lock-reset')?.classList.toggle('hidden', demo);
  $('#lock-modal')?.classList.add('open');
  if (wasSignedIn) { try { nav('overview'); } catch {} }
  $('#lock-modal')?.setAttribute('data-email', email || '');
}
$('#lock-close')?.addEventListener('click', () => $('#lock-modal').classList.remove('open'));
$('#lock-reset')?.addEventListener('click', () => {
  const email = $('#lock-modal').getAttribute('data-email') || '';
  $('#lock-modal').classList.remove('open');
  openAuth('reset');
  if (email) $('#reset-email').value = email;
});
$('#sec-recheck')?.addEventListener('click', async () => {
  const btn = $('#sec-recheck'); setBusy(btn, true, 'Checking…');
  try {
    const r = await api('/api/auth/breach-recheck', { method: 'POST', body: '{}' });
    setText('sec-recheck-status', r.status === 'safe' ? `✓ Not found in any known breach (checked by the server just now).`
      : 'The breach database could not be reached; the scheduled watch will try again.');
  } catch (e) { if (!e.locked) setText('sec-recheck-status', e.message); }
  finally { setBusy(btn, false); }
});

$('#form-security')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const current = $('#sec-current').value; const next = $('#sec-new').value;
  const say = (c, t) => authSay('sec', c, t);
  if (!current || !next) { say('bad', 'Enter your current and new password.'); return; }
  if (next !== $('#sec-confirm').value) { say('bad', 'The new passwords do not match.'); return; }
  if (normalizePassword(next) === normalizePassword(current)) { say('bad', 'Choose a password different from the current one.'); return; }
  const btn = $('#sec-submit'); setBusy(btn, true, 'Working…');
  try {
    const ch = await api('/api/auth/change-password/challenge', { method: 'POST', body: '{}' });
    const proof = await hmacHex(await loginSecret(current, ch), ch.nonce);
    const gate = await runBreachGate('change', next, state.auth.email);
    if (!gate.ok) return;
    say('info', 'Re-encrypting your vault in this browser…');
    const items = await api('/api/vault/items');
    const newVaultSalt = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
    let reenc = []; let newCheck = null;
    if (items.length || ch.vault_check_ciphertext) {
      const oldKey = await deriveVaultKey(current, ch.vault_salt_b64, 600000);
      const newKey = await deriveVaultKey(next, newVaultSalt, 600000);
      try {
        if (ch.vault_check_ciphertext) await decryptVaultPayload(ch.vault_check_ciphertext, oldKey);
        for (const it of items) reenc.push({ id: it.id, ciphertext_b64: await encryptVaultPayload(await decryptVaultPayload(it.ciphertext_b64, oldKey), newKey) });
      } catch { say('bad', 'Current password is incorrect.'); return; }
      newCheck = await encryptVaultPayload({ marker: 'PRIVPASS_VAULT_CHECK_V1', createdAt: new Date().toISOString() }, newKey);
    }
    const cred = await newCredential(next);
    const r = await api('/api/auth/change-password', { method: 'POST', body: JSON.stringify({ nonce: ch.nonce, proof, ...cred,
      score: gate.analysis.score, score_label: gate.analysis.label, breached: false, breach_gate: gate.evidence, vault_salt_b64: newVaultSalt, vault_check_ciphertext: newCheck, items: reenc }) });
    try { lockVault(true); } catch {}
    state.auth.must_change_password = false; securityForced = false;
    say('good', `Password changed. ${r.reencrypted} vault item(s) re-encrypted locally; other sessions signed out.`);
    $('#sec-forced').classList.add('hidden'); $('#security-close').classList.remove('hidden');
    ['sec-current', 'sec-new', 'sec-confirm'].forEach((id) => { $('#' + id).value = ''; });
    loadBell();
  } catch (err) { say('bad', /incorrect|invalid credentials/i.test(err.message) ? 'Current password is incorrect.' : err.message); }
  finally { setBusy(btn, false); }
});

const b64uToBuf = (s) => { let v = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (v.length % 4) v += '='; return Uint8Array.from(atob(v), (c) => c.charCodeAt(0)).buffer; };
const bufToB64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function passkeysSupported() { return !!(window.PublicKeyCredential && navigator.credentials); }

async function loadPasskeys() {
  const list = $('#passkey-list'); if (!list) return;
  try {
    const rows = await api('/api/auth/passkeys');
    list.innerHTML = rows.length ? rows.map((p) => `<div class="passkey-row"><span>🔑 <b>${escapeHtml(p.name)}</b><small>added ${new Date(p.created_at + 'Z').toLocaleDateString()}${p.last_used_at ? ` · last used ${new Date(p.last_used_at + 'Z').toLocaleString()}` : ''}</small></span><button class="mini-action pk-del" data-id="${p.id}">Remove</button></div>`).join('') : '<div class="muted small">No passkeys yet.</div>';
    $$('.pk-del').forEach((b) => b.addEventListener('click', async () => { await api(`/api/auth/passkeys/${b.dataset.id}`, { method: 'DELETE', body: '{}' }); loadPasskeys(); }));
  } catch (e) { list.innerHTML = `<div class="muted small">${escapeHtml(e.message)}</div>`; }
}
$('#passkey-add')?.addEventListener('click', async () => {
  const say = (c, t) => authSay('pk', c, t);
  if (!passkeysSupported()) { say('bad', 'This browser does not support passkeys.'); return; }
  try {
    const opts = await api('/api/auth/passkeys/register/begin', { method: 'POST', body: '{}' });
    const cred = await navigator.credentials.create({ publicKey: { ...opts, challenge: b64uToBuf(opts.challenge), user: { ...opts.user, id: b64uToBuf(opts.user.id) },
      excludeCredentials: (opts.excludeCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })) } });
    const credential = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults?.() || {},
      response: { clientDataJSON: bufToB64u(cred.response.clientDataJSON), attestationObject: bufToB64u(cred.response.attestationObject), transports: cred.response.getTransports?.() || [] } };
    const name = /Mac|iPhone|iPad/.test(navigator.userAgent) ? 'Apple passkey' : /Android/.test(navigator.userAgent) ? 'Android passkey' : /Windows/.test(navigator.userAgent) ? 'Windows Hello' : 'Passkey';
    await api('/api/auth/passkeys/register/finish', { method: 'POST', body: JSON.stringify({ credential, name }) });
    say('good', 'Passkey added. Next time choose “Sign in with a passkey”.');
    loadPasskeys(); loadBell();
  } catch (err) { say('bad', err.name === 'NotAllowedError' ? 'Passkey creation was cancelled.' : err.message); }
});
$('#passkey-signin')?.addEventListener('click', async () => {
  if (!passkeysSupported()) { authSay('signin', 'bad', 'This browser does not support passkeys.'); return; }
  const btn = $('#passkey-signin'); setBusy(btn, true, 'Waiting for your passkey…');
  try {
    const opts = await api('/api/auth/passkeys/login/begin', { method: 'POST', body: '{}' });
    const cred = await navigator.credentials.get({ publicKey: { ...opts, challenge: b64uToBuf(opts.challenge), allowCredentials: (opts.allowCredentials || []).map((c) => ({ ...c, id: b64uToBuf(c.id) })) } });
    const credential = { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults?.() || {},
      response: { clientDataJSON: bufToB64u(cred.response.clientDataJSON), authenticatorData: bufToB64u(cred.response.authenticatorData),
        signature: bufToB64u(cred.response.signature), userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null } };
    const data = await api('/api/auth/passkeys/login/finish', { method: 'POST', body: JSON.stringify({ credential }) });
    state.auth = data; await ensureCsrf(); updateAuthUI(); closeAuth();
    toast(`Signed in with a passkey as ${data.email}. No password was used.`);
    nav(data.role === 'admin' ? 'command' : 'overview');
  } catch (err) { authSay('signin', 'bad', err.name === 'NotAllowedError' ? 'Passkey sign-in was cancelled.' : err.message); }
  finally { setBusy(btn, false); }
});

// ---------------------------------------------------------------- live privacy proof drawer
(function () {
  const PP = window.PrivacyProof; if (!PP) return;
  const row = (e) => `<div class="proof-row ${e.verdict.toLowerCase()} ${e.external ? 'ext' : ''}"><span class="proof-verdict">${e.verdict === 'LEAK' ? '✗ LEAK' : e.verdict === 'CLEAN' ? '✓ CLEAN' : '…'}</span>
    <span class="proof-req"><b>${escapeHtml(e.method)}</b> <code>${escapeHtml(e.host)}${escapeHtml(e.path.length > 70 ? e.path.slice(0, 70) + '…' : e.path)}</code>
    <small>${e.bytes} bytes${e.note ? ' · ' + escapeHtml(e.note) : ''}${e.leak.length ? ' · <b class="bad">' + escapeHtml(e.leak.join(', ')) + '</b>' : ''}</small></span><time>${e.t.toLocaleTimeString()}</time></div>`;
  function render() {
    const s = PP.stats();
    setText('proof-count', s.total); setText('proof-total', s.total); setText('proof-external', s.external); setText('proof-leaks-n', s.leaks);
    setText('proof-leaks', `${s.leaks} leak${s.leaks === 1 ? '' : 's'}`);
    $('#proof-fab')?.classList.toggle('alarm', s.leaks > 0);
    const list = $('#proof-list');
    if (list && $('#proof-drawer').classList.contains('open')) list.innerHTML = PP.log.slice(-80).reverse().map(row).join('') || '<div class="empty-state">No requests yet.</div>';
  }
  PP.onEntry(() => render());
  $('#proof-fab')?.addEventListener('click', () => { $('#proof-drawer').classList.toggle('open'); render(); });
  $('#proof-close')?.addEventListener('click', () => $('#proof-drawer').classList.remove('open'));
  render();
})();

// ---------------------------------------------------------------- guided tour
const TOUR_ALL = [
  { view: 'overview', sel: '.hero-copy h1', title: 'Two leaks, one product', text: 'PrivPass Shield stops breached passwords at signup and leaked keys at merge — and uses AI that never sees a secret.' },
  { view: 'password', sel: '#pw-input', title: 'Measure guessability, not decoration', text: 'Type any password. Pattern rules and three attack models score it — all in the browser, nothing is sent.', enter: () => { $('#pw-input').value = 'harsh khandelwal'; $('#pw-input').type = 'text'; refreshPasswordAnalysis(); } },
  { view: 'password', sel: '#neural-panel', title: 'Three attack models, the fastest wins', text: 'A neural network trained on leaked passwords, ranked word & name lists (first names + surnames from many countries) and the 1M leaked list. A real name falls in seconds, and the panel says why.' },
  { view: 'password', sel: '#privacy-receipt', title: 'k-anonymity + offline corpus', text: 'Only a 5-character hash prefix goes to Have I Been Pwned — and a 1-million-password corpus is checked fully offline.' },
  { view: 'password', sel: '#proof-fab', title: 'Don\'t trust us — watch', text: 'This live inspector checks every request the page sends for your password or its hash. Open it any time.', enter: () => $('#proof-drawer').classList.add('open'), leave: () => $('#proof-drawer').classList.remove('open') },
  { view: 'secrets', sel: '#dropzone', title: 'SecretGuard', text: 'Drop a repo ZIP (with .git for full history) or paste a GitHub URL. Secrets, risky code, and keys that were “deleted” but live on in history.' },
  { view: 'secrets', sel: '.honey-panel', title: 'Honeytokens', text: 'Plant bait keys. Anyone who tries one triggers a CRITICAL alert with their IP — you learn about the breach before the attacker gets anywhere.' },
  { view: 'secrets', sel: '.findings-panel', title: 'ML + AI on every finding', text: 'An ML classifier (99% recall vs 43% for rules) explains each score; ✦ AI fix writes the patch and the provider rotation runbook — from masked code only.' },
  { view: 'exposure', sel: '#xp-map', title: 'Your attack surface, mapped', text: 'Password, sign-in factors, sessions, repositories and bait keys around one identity. Red lines are live attack paths; each dot is an open finding. Hover any node.' },
  { view: 'exposure', sel: '#xp-paths', title: 'Attack paths, ranked', text: 'Entry point → how it is used → impact, with the exact fix. “Fix →” jumps straight to the finding or setting that closes it.' },
  { view: 'ai', sel: '#model-grid', title: 'AI Lab', text: 'Three models trained and evaluated for this project, with honest benchmarks against baselines.' },
  { view: 'ai', sel: '#anomaly-panel', title: 'Login attack detection', text: 'An Isolation Forest flags credential stuffing, brute force and account enumeration from sign-in telemetry (only HMACs of emails).' },
  { view: 'ai', sel: '.copilot', title: 'Security copilot', text: 'Ask in plain English. It answers only from read-only, role-scoped tools over redacted data — and can write the incident report.' },
  { view: 'command', sel: '.sla-strip', role: 'admin', title: 'Run it like a security team', text: 'Fix deadlines per severity, time-to-contain and time-to-rotate, honeytoken trips, and the “X% of test accounts” breach audit.' },
  { view: 'command', sel: '#sim-panel', role: 'admin', demo: true, title: 'A sandbox, separate from real accounts', text: 'Demo accounts live in their own workspace: they only ever see demo data, can’t change passwords or manage users, and never send real alerts. Load or remove the sample story here.' },
];
let TOUR = TOUR_ALL;
async function tourPrepare() {
  // The tour tells the whole story, so it needs a signed-in admin and some data to show.
  if (!state.auth) {
    try {
      const info = await api('/api/demo/info');
      if (info.demo_mode) { await signIn(info.admin.email, info.admin.password); toast('Signed in as the demo admin for the tour (sandbox with sample data only).'); }
    } catch {}
  }
  if (state.auth?.workspace === 'demo' && state.auth.role === 'admin') {
    try {
      const st = await api('/api/admin/simulations');
      const overview = await api('/api/admin/overview');
      if (!st.seeded_items && !overview.secret_findings) { await api('/api/admin/simulate/seed', { method: 'POST', body: '{}' }); loadBell(); }
    } catch {}
  }
  TOUR = TOUR_ALL.filter((s) => (!s.role || state.auth?.role === s.role) && (!s.demo || state.auth?.workspace === 'demo'));
}
async function tourStart() {
  const btn = $('#tour-start'); if (btn) btn.disabled = true;
  try { await tourPrepare(); } finally { if (btn) btn.disabled = false; }
  tourShow(0);
}
let tourIdx = -1;
function tourShow(i) {
  const prev = TOUR[tourIdx]; if (prev?.leave) prev.leave();
  tourIdx = i; const step = TOUR[i];
  if (!step) return tourEnd();
  nav(step.view); if (step.enter) step.enter();
  $('#tour').classList.remove('hidden');
  setTimeout(() => {
    const el = $(step.sel); const spot = $('#tour-spot'); const card = $('#tour-card');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setTimeout(() => {
        const r = el.getBoundingClientRect(); const pad = 10;
        Object.assign(spot.style, { top: `${r.top - pad}px`, left: `${r.left - pad}px`, width: `${r.width + pad * 2}px`, height: `${Math.min(r.height + pad * 2, innerHeight - 40)}px` });
        const ch = card.offsetHeight || 230; const cw = card.offsetWidth || 420;
        const below = r.bottom + ch + 30 < innerHeight;
        const top = below ? r.bottom + 18 : r.top - ch - 18;
        // Always keep the card fully inside the viewport, even for tall targets.
        Object.assign(card.style, { top: `${Math.min(Math.max(16, top), innerHeight - ch - 16)}px`, left: `${Math.min(Math.max(16, r.left), innerWidth - cw - 16)}px` });
      }, 420);
    }
    setText('tour-step', `STEP ${i + 1} OF ${TOUR.length}`); setText('tour-title', step.title); setText('tour-text', step.text);
    $('#tour-next').textContent = i === TOUR.length - 1 ? 'Finish' : 'Next';
    $('#tour-back').disabled = i === 0;
  }, 250);
}
function tourEnd() { const s = TOUR[tourIdx]; if (s?.leave) s.leave(); tourIdx = -1; $('#tour').classList.add('hidden'); }
$('#tour-start')?.addEventListener('click', tourStart);
$('#judge-tour')?.addEventListener('click', (e) => { e.stopImmediatePropagation(); tourStart(); }, true);
$('#tour-next')?.addEventListener('click', () => tourShow(tourIdx + 1));
$('#tour-back')?.addEventListener('click', () => tourShow(Math.max(0, tourIdx - 1)));
$('#tour-skip')?.addEventListener('click', tourEnd);
document.addEventListener('keydown', (e) => { if (tourIdx < 0) return; if (e.key === 'ArrowRight') tourShow(tourIdx + 1); if (e.key === 'ArrowLeft') tourShow(Math.max(0, tourIdx - 1)); if (e.key === 'Escape') tourEnd(); });

// ---------------------------------------------------------------- view hooks
const _nav = nav;
nav = function (name) {  // eslint-disable-line no-func-assign
  _nav(name);
  if (name === 'secrets') loadHoneytokens();
};
startBell();

// ---------------------------------------------------------------- admin demo simulations
$('#sec-sim-clear')?.addEventListener('click', async () => {
  try {
    await api('/api/admin/simulations/clear', { method: 'POST', body: '{}' });
    state.auth.must_change_password = false; securityForced = false;
    $('#security-modal').classList.remove('open'); toast('Simulation removed — your account is unlocked.'); loadBell(); loadSimPanel();
  } catch (e) { toast(e.message); }
});
function simSummary(c) {
  const parts = [];
  if (c.simulated_breached_users) parts.push(`${c.simulated_breached_users} locked account${c.simulated_breached_users > 1 ? 's' : ''}`);
  if (c.simulated_login_events) parts.push(`${c.simulated_login_events} fake sign-ins`);
  if (c.seeded_items) parts.push('sample data loaded');
  if (c.simulation_alerts) parts.push(`${c.simulation_alerts} alert${c.simulation_alerts > 1 ? 's' : ''}`);
  const el = $('#sim-summary'); if (!el) return;
  el.textContent = parts.length ? `Active: ${parts.join(' · ')}` : 'No simulation data';
  el.classList.toggle('active', parts.length > 0);
  $('#sim-clear').disabled = !parts.length;
}
async function loadSimPanel() {
  if (state.auth?.role !== 'admin' || state.auth?.workspace !== 'demo' || !$('#sim-panel')) return;
  try {
    const [users, status] = await Promise.all([api('/api/admin/users'), api('/api/admin/simulations')]);
    const sel = $('#sim-user'); const keep = sel.value;
    sel.innerHTML = users.filter((u) => u.active && u.email !== state.auth.email && !u.breach_locked).map((u) => `<option value="${escapeHtml(u.id)}">${escapeHtml(u.email)}${u.email === state.auth.email ? ' (you)' : ''}${status.breached_users.includes(u.email) ? ' — locked' : ''}</option>`).join('');
    const demo = users.find((u) => u.email === 'user@privpass.local');
    sel.value = keep && users.some((u) => u.id === keep) ? keep : (demo?.id || sel.value);
    simSummary(status);
  } catch (e) { setText('sim-summary', e.message); }
}
$('#sim-breach')?.addEventListener('click', async () => {
  const btn = $('#sim-breach'); setBusy(btn, true, 'Simulating…');
  try {
    const r = await api('/api/admin/simulate/breach', { method: 'POST', body: JSON.stringify({ user_id: $('#sim-user').value }) });
    authSay('sim', 'good', `${r.target} is now locked and signed out on every device, exactly as the breach watch would do. Try signing in as them to see the lock screen, then press “Remove simulation data”.`);
    simSummary(r); loadBell(); loadSimPanel();
    if (typeof loadAdmin === 'function') loadAdmin();
  } catch (e) { authSay('sim', 'bad', e.message); }
  finally { setBusy(btn, false); }
});
$('#sim-attack')?.addEventListener('click', async () => {
  const btn = $('#sim-attack'); setBusy(btn, true, 'Injecting…');
  try {
    const r = await api('/api/ai/anomalies/simulate', { method: 'POST', body: '{}' });
    authSay('sim', 'good', `Injected simulated traffic — the Isolation Forest flagged ${r.anomalous} attack window(s). Open AI Lab to see them.`);
    loadBell(); loadSimPanel();
  } catch (e) { authSay('sim', 'bad', e.message); }
  finally { setBusy(btn, false); }
});
$('#breach-watch-run')?.addEventListener('click', async () => {
  const btn = $('#breach-watch-run'); setBusy(btn, true, 'Checking…');
  try {
    const r = await api('/api/admin/breach-watch/run', { method: 'POST', body: '{}' });
    setText('breach-watch-status', `Checked ${r.checked} account(s) against HIBP on the server: ${r.safe} clean, ${r.locked} locked${r.unavailable ? `, ${r.unavailable} couldn't be checked (HIBP unreachable)` : ''}${r.legacy ? `, ${r.legacy} will upgrade at next sign-in` : ''}. ${r.interval_minutes > 0 ? `Runs automatically every ${Math.round(r.interval_minutes / 60 * 10) / 10} h.` : 'Automatic re-checks are switched off (PRIVPASS_BREACH_WATCH_MINUTES=0).'}`);
    if (typeof loadAdmin === 'function') loadAdmin(); loadBell();
  } catch (e) { setText('breach-watch-status', e.message); }
  finally { setBusy(btn, false); }
});
$('#sim-seed')?.addEventListener('click', async () => {
  const btn = $('#sim-seed'); setBusy(btn, true, 'Loading…');
  try {
    const r = await api('/api/admin/simulate/seed', { method: 'POST', body: '{}' });
    authSay('sim', 'good', `Demo data loaded: ${r.repositories} repositories, ${r.findings} findings, ${r.honeytoken_trips} honeytoken trips, ${r.gate_attempts} breach-gate attempts. Open Exposure, Incidents or AI Lab to see it.`);
    simSummary(r); loadBell(); loadSimPanel();
    if (typeof loadAdmin === 'function') loadAdmin();
  } catch (e) { authSay('sim', 'bad', e.message); }
  finally { setBusy(btn, false); }
});
$('#sim-clear')?.addEventListener('click', async () => {
  if (!confirm('Remove all simulation data? Simulated sign-ins and alerts are deleted and simulated accounts are unlocked. Real data is not touched.')) return;
  const btn = $('#sim-clear'); setBusy(btn, true, 'Removing…');
  try {
    const r = await api('/api/admin/simulations/clear', { method: 'POST', body: '{}' });
    authSay('sim', 'good', `Removed ${r.removed_login_events} simulated sign-in(s), ${r.removed_alerts} alert(s)${r.removed_demo_data ? ' and the sample data' : ''}; unlocked ${r.users_unlocked} account(s).`);
    if (typeof loadAdmin === 'function') loadAdmin();
    if (state.auth.must_change_password) { const me = await api('/api/auth/me'); state.auth.must_change_password = me.must_change_password; }
    if (!state.auth.must_change_password) { securityForced = false; $('#security-modal').classList.remove('open'); }
    simSummary(r); loadBell(); loadSimPanel();
  } catch (e) { authSay('sim', 'bad', e.message); }
  finally { setBusy(btn, false); }
});
const _navSim = nav;
nav = function (name) { _navSim(name); if (name === 'command') loadSimPanel(); };  // eslint-disable-line no-func-assign
