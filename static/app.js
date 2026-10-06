const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];

// Storage can be unavailable in privacy-restricted/file/document contexts. Never let a
// convenience preference kill the whole application bootstrap.
const safeStorage = {
  get(key) { try { return window.localStorage.getItem(key); } catch { return null; } },
  set(key, value) { try { window.localStorage.setItem(key, value); } catch {} },
  remove(key) { try { window.localStorage.removeItem(key); } catch {} },
};

const state = {
  theme: safeStorage.get('pp-theme') || 'dark',
  hibp: null,
  auth: null,
  analyzeTimer: null,
  vaultKey: null,
  vaultConfig: null,
  vaultItems: [],
  vaultRecords: [],
  vaultAutoLockTimer: null,
  secretFindings: [],
};

document.documentElement.dataset.theme = state.theme === 'light' ? 'light' : 'dark';

function toast(message) {
  const el = $('#toast');
  if (!el) return;
  el.textContent = message;
  el.classList.add('show');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.remove('show'), 3600);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, (c) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
}

function nav(name) {
  $$('.view').forEach((view) => view.classList.remove('active'));
  $('#view-' + name)?.classList.add('active');
  $$('[data-nav]').forEach((button) => button.classList.toggle('active', button.dataset.nav === name));
  window.scrollTo({ top: 0, behavior: 'instant' });
  if (name === 'overview') loadPublic();
  if (name === 'secrets') loadFindings();
  if (name === 'command') loadAdmin();
  if (name === 'demo') loadDemoInfo();
  if (name === 'vault') loadVaultView();
  if (name === 'exposure') loadExposureGraph();
  if (name === 'incidents') loadIncidents();
  if (name === 'ai') loadAiLab();
}

$$('[data-nav]').forEach((button) => button.addEventListener('click', () => nav(button.dataset.nav)));

$('#theme-toggle')?.addEventListener('click', () => {
  state.theme = state.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = state.theme;
  safeStorage.set('pp-theme', state.theme);
});

function readCookie(name) {
  const match = document.cookie.split('; ').find((row) => row.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

// CSRF: the server issues a double-submit token (pp_csrf cookie) and, after sign-in, binds it to the
// session. Every state-changing request echoes it in X-CSRF-Token.
let csrfReady = null;
function ensureCsrf(force = false) {
  if (!force && readCookie('pp_csrf')) return Promise.resolve();
  if (!csrfReady || force) csrfReady = fetch('/api/csrf', { credentials: 'same-origin' }).catch(() => {});
  return csrfReady;
}

let lockEmailHint = '';   // email of the account being signed in to, for the breach-lock screen
async function api(url, options = {}, retried = false) {
  const method = (options.method || 'GET').toUpperCase();
  const fetchOptions = { ...options, credentials: 'same-origin', headers: { ...(options.headers || {}) } };
  if (options.body && !(options.body instanceof FormData)) fetchOptions.headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && method !== 'HEAD') {
    await ensureCsrf();
    fetchOptions.headers['X-CSRF-Token'] = readCookie('pp_csrf');
  }
  const response = await fetch(url, fetchOptions);
  let data = {};
  try { data = await response.json(); } catch {}
  if (response.status === 403 && /csrf/i.test(data.detail || '') && !retried) {
    await ensureCsrf(true);
    return api(url, options, true);
  }
  if (response.status === 423) {             // password breached: account locked by the server
    showBreachLock(data.detail || '', state.auth?.email || lockEmailHint);
    const err = new Error(data.detail || 'Account locked'); err.locked = true; throw err;
  }
  if (response.status === 401 && state.auth && /not authenticated|session expired|account inactive/i.test(data.detail || '')) {
    state.auth = null;
    signOut('Your session expired — please sign in again.');
  }
  if (!response.ok) throw new Error(data.detail || data.message || `HTTP ${response.status}`);
  return data;
}

function bytesToB64(bytes) {
  let text = '';
  bytes.forEach((b) => { text += String.fromCharCode(b); });
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64ToBytes(value) {
  let v = value.replace(/-/g, '+').replace(/_/g, '/');
  while (v.length % 4) v += '=';
  const binary = atob(v);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

// NIST SP 800-63B: normalize Unicode (NFKC) before hashing so the same password typed on
// different keyboards/IMEs always produces the same verifier and the same HIBP hash.
function normalizePassword(password) {
  return String(password ?? '').normalize('NFKC');
}

async function deriveVerifier(password, saltB64) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(normalizePassword(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations: 310000, hash: 'SHA-256' }, key, 256);
  return bytesToB64(new Uint8Array(bits));
}

// ---- 7.3 bound credentials (see app/breachwatch.py). The browser sends the 5-char SHA-1 prefix and a slow
// "watch" value; the server checks them against HIBP itself and derives the login verifier FROM them, so a
// breached password can never be used to sign in, even with a modified browser. The password, its full SHA-1
// and the SHA-1 suffix never leave this tab.
async function pbkdf2B64(secretBytes, saltB64, iterations) {
  const key = await crypto.subtle.importKey('raw', secretBytes, 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations, hash: 'SHA-256' }, key, 256);
  return bytesToB64(new Uint8Array(bits));
}
async function watchMaterial(password, watchSaltB64) {
  const h = (await sha1Hex(normalizePassword(password))).toUpperCase();
  return { prefix: h.slice(0, 5), watch_b64: await pbkdf2B64(new TextEncoder().encode(h), watchSaltB64, 2000) };
}
async function newCredential(password) {
  const rnd = () => bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
  const salt_b64 = rnd(); const watch_salt_b64 = rnd();
  return { salt_b64, watch_salt_b64, ...(await watchMaterial(password, watch_salt_b64)) };
}
// The login secret for a challenge: v2 (bound to the breach-watch value) or v1 (legacy, upgraded at sign-in).
async function loginSecret(password, ch) {
  if ((ch.kdf || 1) >= 2) {
    const m = await watchMaterial(password, ch.watch_salt_b64);
    return pbkdf2B64(new TextEncoder().encode(`${m.watch_b64}.${m.prefix}`), ch.salt_b64, 310000);
  }
  return deriveVerifier(password, ch.salt_b64);
}

async function hmacHex(secretB64, message) {
  const key = await crypto.subtle.importKey('raw', b64ToBytes(secretB64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const bytes = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha1Hex(text) {
  const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

const COMMON = new Set([
  'password','password1','password123','123456','12345678','123456789','1234567890','qwerty','qwerty123',
  'asdfgh','admin','letmein','welcome','iloveyou','abc123','monkey','dragon','football','secret','changeme',
  'login','passw0rd','trustno1','sunshine','princess','master','hello','freedom','whatever','zaq12wsx','root','user'
]);
const COMMON_WORDS = new Set([
  'admin','apple','orange','microsoft','google','company','finance','password','welcome','summer','winter','spring','autumn',
  'football','dragon','monkey','shadow','secret','master','letmein','hello','india','delhi','ajmer','college','student',
  'github','office','corporate','support','security','manager','access','system','testing','test','demo','oracle','database',
  'server','network','cloud','project','privpass'
]);
const IDENTITY_TOKENS = new Set([
  'divy','divya','mathur','rahul','rohit','amit','ankit','anil','arjun','aditya','aman','ashish','ayush','deepak','dev',
  'gaurav','harsh','karan','kunal','manish','mohit','nikhil','pranav','priyansh','raj','ravi','roshan','sachin','sahil',
  'sameer','sanjay','shivam','shubham','sumit','surya','tarun','varun','vijay','vivek','yash','yuvraj','neha','priya',
  'pooja','riya','simran','shruti','kavya','ananya','isha','aisha','sonam','swati','megha','nisha','komal','tanya','kriti',
  'akanksha','muskan','divyansh','sharma','verma','gupta','singh','patel','mehta','jain','agarwal','kapoor','malhotra',
  'saxena','joshi','kumar'
]);
const KEYBOARD_PATTERNS = ['qwertyuiop','asdfghjkl','zxcvbnm','1234567890','0987654321','qazwsx','qweasdzxc','1qaz2wsx'];

function maxRun(text) {
  if (!text) return 0;
  let best = 1, run = 1;
  for (let i = 1; i < text.length; i += 1) {
    run = text[i] === text[i - 1] ? run + 1 : 1;
    best = Math.max(best, run);
  }
  return best;
}

function repeatedChunks(text) {
  const hits = [];
  for (let size = 2; size <= Math.min(8, Math.floor(text.length / 2)); size += 1) {
    for (let i = 0; i <= text.length - size * 2; i += 1) {
      const chunk = text.slice(i, i + size);
      if (chunk === text.slice(i + size, i + size * 2)) hits.push(chunk);
    }
  }
  return [...new Set(hits)].sort((a, b) => b.length - a.length);
}

function sequenceRun(text) {
  let best = 0;
  for (const direction of [1, -1]) {
    let run = 1;
    for (let i = 1; i < text.length; i += 1) {
      const delta = text.charCodeAt(i) - text.charCodeAt(i - 1);
      if (delta === direction) { run += 1; best = Math.max(best, run); } else run = 1;
    }
  }
  return best;
}

function embeddedTokens(lower, set) {
  return [...set].filter((token) => token.length >= 4 && lower.includes(token)).sort((a, b) => b.length - a.length || a.localeCompare(b));
}

function trigramRepetition(text) {
  if (text.length < 6) return 0;
  const grams = [];
  for (let i = 0; i < text.length - 2; i += 1) grams.push(text.slice(i, i + 3).toLowerCase());
  return grams.length - new Set(grams).size;
}

function tokenCoverage(lower, tokens, length) {
  if (!tokens?.length || !length) return 0;
  let total = 0;
  for (const token of tokens) {
    let start = 0;
    while (true) {
      const idx = lower.indexOf(token, start);
      if (idx < 0) break;
      total += token.length;
      start = idx + Math.max(1, token.length);
    }
  }
  return Math.min(1, total / Math.max(1, length));
}

function analyzePasswordCore(password, contexts = [], generated = false) {
  const p = String(password || '').normalize('NFKC');
  if (!p) return { score: 0, label: 'Waiting', verdict: 'REVIEW', length: 0, log10Guesses: 0, bits: null, uniqueRatio: 0, reasons: ['Type a password to begin local analysis.'], context: [], identityHits: [], dictionaryHits: [], flags: {}, why: 'Nothing has been analyzed yet.', generated };
  const n = p.length;
  const lower = p.toLowerCase();
  const meaningful = [...p].filter((ch) => /[A-Za-z0-9]/.test(ch)).map((ch) => ch.toLowerCase());
  const ratio = meaningful.length ? new Set(meaningful).size / meaningful.length : 0;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((rx) => rx.test(p)).length;
  const words = (p.match(/[A-Za-z]{3,}/g) || []).map((x) => x.toLowerCase());
  const common = COMMON.has(lower);
  const repeats = repeatedChunks(p);
  const run = maxRun(p);
  const seq = sequenceRun(p);
  const keyboard = KEYBOARD_PATTERNS.some((item) => lower.includes(item));
  const date = /(?:^|[^0-9])(?:19|20)\d{2}(?:$|[^0-9])/.test(p) || /(?:^|[^0-9])(?:0?[1-9]|[12]\d|3[01])[-/](?:0?[1-9]|1[0-2])[-/]\d{2,4}(?:$|[^0-9])/.test(p);
  const digitOnly = /^\d+$/.test(p);
  const letterOnly = /^[A-Za-z]+$/.test(p);
  const alternating = /(.{2,4})\1{2,}/i.test(p);
  const identityHits = embeddedTokens(lower, IDENTITY_TOKENS);
  const dictionaryHits = embeddedTokens(lower, COMMON_WORDS).filter((token) => token.length >= 5);
  const trigram = trigramRepetition(p);
  const repeatedWord = words.length > new Set(words).size;
  const separatorPhrase = words.length >= 3 && /[\s-]/.test(p);
  const context = contexts.filter((item) => item && item.length >= 3 && lower.includes(item.toLowerCase()));
  const identityLike = identityHits.length > 0 || context.length > 0;
  const dictionaryLike = dictionaryHits.length > 0;
  const identityCoverage = Math.max(tokenCoverage(lower, identityHits.concat(context), n), Math.min(1, context.reduce((acc, x) => acc + x.length, 0) / Math.max(1, n)));
  const dictionaryCoverage = tokenCoverage(lower, dictionaryHits, n);

  let score;
  let constructionBits = null;
  if (generated) {
    const alphabet = 70;
    const wordCount = (p.match(/-/g) || []).length + 1;
    constructionBits = (wordCount >= 4 && p.includes('-') && /^[a-z]+(?:-[a-z]+)+$/i.test(p))
      ? Math.round(wordCount * Math.log2(2048) * 10) / 10
      : Math.round(n * Math.log2(alphabet) * 10) / 10;
    score = constructionBits >= 120 ? 100 : Math.min(99, Math.round(78 + constructionBits * 0.18));
  } else {
    const lengthComponent = Math.min(38, Math.max(0, (n - 7) * 2.15));
    const diversity = Math.min(20, classes * 4 + ratio * 6);
    const uniqueness = 6 * Math.min(1, Math.max(0, (ratio - 0.40) / 0.60));
    score = 5 + lengthComponent + diversity + uniqueness;
    if (separatorPhrase && words.length >= 4 && new Set(words).size === words.length && identityCoverage < 0.12 && dictionaryCoverage < 0.18) score += 28;
    if (identityCoverage > 0.65) score -= 42; else if (identityCoverage > 0.40) score -= 28; else if (identityCoverage > 0.20) score -= 18; else if (identityCoverage > 0.08) score -= 8;
    if (dictionaryCoverage > 0.60) score -= 30; else if (dictionaryCoverage > 0.35) score -= 18; else if (dictionaryCoverage > 0.15) score -= 9;
    if (digitOnly) { if (n < 10) score -= 35; else if (n < 15) score -= 24; else if (seq >= 4 || repeats.length || alternating) score -= 18; else { score -= 6; if (n >= 18 && ratio >= 0.55) score = Math.max(score, 62); } }
    if (letterOnly && n < 20) score -= 5;
    if (run >= 7) score -= 20; else if (run >= 5) score -= 9; else if (run >= 4) score -= 4;
    if (repeats.length) score -= Math.min(24, 8 + 4 * repeats.length);
    if (repeatedWord) score -= 12;
    if (seq >= 8) score -= 16; else if (seq >= 5) score -= 8; else if (seq >= 4) score -= 3;
    if (keyboard) score -= 24;
    if (date) score -= 8;
    if (alternating) score -= 10;
    if (trigram >= 6) score -= 8; else if (trigram >= 3) score -= 3;
    if (ratio < 0.35 && n >= 12) score -= 8; else if (ratio < 0.50 && n >= 12) score -= 3;
    if (n >= 24 && classes >= 3 && ratio >= 0.65 && identityCoverage < 0.08 && dictionaryCoverage < 0.12) score += 18;
    // Long, high-diversity human strings should not be crushed merely because they contain
    // a small amount of identity/dictionary context. Keep the warning visible, but score the
    // predictable portion proportionally to the whole string.
    if (n >= 40 && classes >= 3 && ratio >= 0.55 && run <= 4 && seq < 6 && !keyboard && repeats.length <= 1 && identityCoverage <= 0.30 && dictionaryCoverage <= 0.25) score = Math.max(score, 90);
    else if (n >= 40 && classes >= 3 && ratio >= 0.45 && run <= 4 && seq < 6 && !keyboard && repeats.length <= 1 && identityCoverage <= 0.35 && dictionaryCoverage <= 0.30) score = Math.max(score, 86);
    else if (n >= 40 && classes >= 3 && ratio >= 0.30 && run <= 4 && seq < 5 && !keyboard && repeats.length <= 1 && identityCoverage <= 0.08 && dictionaryCoverage <= 0.12) score = Math.max(score, 88);
    else if (n >= 24 && classes >= 3 && ratio >= 0.45 && run <= 4 && seq < 5 && !keyboard && repeats.length <= 1 && identityCoverage <= 0.20 && dictionaryCoverage <= 0.20) score = Math.max(score, 84);
    if (separatorPhrase && words.length >= 4 && new Set(words).size === words.length && identityCoverage < 0.12 && dictionaryCoverage < 0.18) score = Math.max(score, 88);
    score = Math.max(n >= 10 ? 4 : 0, Math.min(96, score));
  }
  if (!generated && n < 8) score = Math.min(score, 12);
  if (!generated && n <= 12 && identityCoverage >= 0.75) score = Math.min(score, 12);
  if (!generated && digitOnly && n < 12) score = Math.min(score, 20);
  if (common) score = 4;

  const log10 = generated ? Math.round((constructionBits / Math.log2(10)) * 100) / 100 : Math.round(Math.max(0.3, Math.min(20, 1.2 + score * 0.19)) * 100) / 100;
  const bits = generated ? constructionBits : Math.round(log10 * Math.log2(10) * 10) / 10;
  let label = 'Excellent'; if (common || score < 20) label = 'Critical'; else if (score < 45) label = 'Weak'; else if (score < 65) label = 'Fair'; else if (score < 85) label = 'Strong';
  const reasons = [];
  if (n < 15) reasons.push('Below the 15-character password-only baseline');
  if (common) reasons.push('Matches a commonly guessed password');
  if (identityHits.length) reasons.push(`Identity-like token detected: ${identityHits[0]}`);
  if (context.length) reasons.push('Contains supplied account or organization context');
  if (dictionaryHits.length) reasons.push(`Common word/pattern detected: ${dictionaryHits[0]}`);
  if (run >= 3) reasons.push(`Repeated-character run of ${run}`);
  if (repeats.length) reasons.push(`Repeated substring pattern detected (${repeats[0]})`);
  if (repeatedWord) reasons.push('Repeated word/token structure detected');
  if (seq >= 3) reasons.push(`Predictable sequence of ${seq}+ characters`);
  if (keyboard) reasons.push('Keyboard-pattern sequence detected');
  if (date) reasons.push('Contains a likely year/date pattern');
  if (digitOnly) reasons.push('Numeric-only password uses a smaller alphabet; long random numeric secrets can still be useful');
  if (trigram >= 2) reasons.push('Repeated 3-character patterns suggest human-made structure');
  if (separatorPhrase && words.length >= 4 && new Set(words).size === words.length) reasons.push('Distinct multi-word passphrase structure detected');
  if (generated) reasons.push('Generated locally with Web Crypto; construction entropy is shown separately');
  if (!reasons.length) reasons.push('No dominant low-effort guessing pattern detected');
  const verdict = common || score < 20 ? 'BLOCK' : (score < 60 || identityLike || dictionaryLike || digitOnly || keyboard || n < 15) ? 'REVIEW' : 'ACCEPT';
  return { score: Math.round(score), label, verdict, length: n, log10Guesses: log10, bits, constructionBits, uniqueRatio: ratio, reasons: reasons.slice(0, 10), context, identityHits, dictionaryHits,
    flags: { run, repeated: repeats.length > 0, repeatedWord, keyboard, sequence: seq >= 3, digitOnly, date, alternating, identityLike, dictionaryLike, trigram, separatorPhrase, generated, identityCoverage, dictionaryCoverage },
    why: `Model guess-rank estimate is about 10^${log10.toFixed(2)}; this is a heuristic, not an exact crack-time promise.`, generated };
}

function updatePasswordUI(result) {
  $('#pw-label').textContent = result.label;
  $('#pw-score').textContent = `${result.score} / 100`;
  $('#pw-bar').style.width = `${result.score}%`;
  $('#pw-length').textContent = result.length;
  $('#pw-bits').textContent = result.bits == null ? '—' : `${result.bits}`;
  $('#pw-guesses').textContent = result.log10Guesses ? `10^${result.log10Guesses}` : '—';
  $('#pw-context').textContent = result.context.length || result.identityHits?.length ? `${(result.context.length || 0) + (result.identityHits?.length || 0)} hit` : 'None';
  $('#pw-pattern').textContent = (result.flags.run >= 3 || result.flags.keyboard || result.flags.sequence || result.flags.repeated || result.flags.repeatedWord || result.flags.identityLike || result.flags.dictionaryLike || result.flags.digitOnly) ? 'High' : result.score < 60 ? 'Medium' : 'Low';
  const setRisk = (id, level, label) => { const el = $(`#${id}`); if (!el) return; el.textContent = label; el.className = `risk-${level}`; };
  setRisk('risk-identity', result.identityHits?.length || result.context?.length ? 'high' : 'low', result.identityHits?.length ? result.identityHits[0].toUpperCase() : (result.context?.length ? 'CONTEXT HIT' : 'NONE'));
  setRisk('risk-dictionary', result.dictionaryHits?.length ? 'high' : 'low', result.dictionaryHits?.length ? result.dictionaryHits[0].toUpperCase() : 'NONE');
  setRisk('risk-numeric', result.flags?.digitOnly || result.flags?.date ? 'high' : 'low', result.flags?.digitOnly ? 'NUMERIC' : (result.flags?.date ? 'DATE/YEAR' : 'NONE'));
  setRisk('risk-repeat', result.flags?.repeated || result.flags?.run >= 3 || result.flags?.repeatedWord || result.flags?.trigram >= 2 ? 'high' : 'low', result.flags?.repeated || result.flags?.run >= 3 || result.flags?.repeatedWord || result.flags?.trigram >= 2 ? 'DETECTED' : 'NONE');
  setRisk('risk-sequence', result.flags?.keyboard || result.flags?.sequence ? 'high' : 'low', result.flags?.keyboard ? 'KEYBOARD' : (result.flags?.sequence ? 'SEQUENCE' : 'NONE'));
  setRisk('risk-source', result.generated ? 'low' : 'medium', result.generated ? 'CSPRNG' : 'HUMAN-CHOSEN');
  $('#pw-verdict').textContent = result.verdict;
  $('#pw-verdict').className = `verdict-chip ${result.verdict.toLowerCase()}`;
  $('#pw-headline').textContent = result.verdict === 'ACCEPT' ? 'No dominant low-effort structure detected.' : result.verdict === 'BLOCK' ? 'Do not use this secret.' : (result.identityHits?.length || result.flags?.digitOnly || result.flags?.dictionaryLike) ? 'Predictable identity, dictionary, or numeric structure dominates length.' : 'Length helps, but predictable structure reduces resistance.';
  $('#pw-why').textContent = result.why;
  $('#pw-reasons').innerHTML = result.reasons.slice(0, 7).map((item) => `<span class="reason">${escapeHtml(item)}</span>`).join('');
}

function contexts() {
  const emailLocal = String(state.auth?.email || '').split('@')[0];
  const values = [$('#pw-context-name')?.value, $('#pw-context-org')?.value, emailLocal, 'privpass', 'acme', 'admin'];
  return values.flatMap((value) => String(value || '').toLowerCase().split(/\s+|[@._-]/)).filter((x) => x.length >= 3);
}

let currentAnalysis = null;
function refreshPasswordAnalysis() {
  const password = $('#pw-input')?.value || '';
  currentAnalysis = analyzePasswordCore(password, contexts(), false);
  updatePasswordUI(currentAnalysis);
  updatePrivacyPreview(password);
  scheduleNeural(password, currentAnalysis);
}

// ---- Neural guessability model (static/ml/password-model.js) - combined conservatively with the rules.
let neuralTimer = null; let neuralSeq = 0;
function scoreLabel(score) { return score < 20 ? 'Critical' : score < 45 ? 'Weak' : score < 65 ? 'Fair' : score < 85 ? 'Strong' : 'Excellent'; }
function scheduleNeural(password, analysis) {
  clearTimeout(neuralTimer);
  const seq = ++neuralSeq;
  if (!password || !window.PrivPassGuess) { resetNeuralPanel(); return; }
  neuralTimer = setTimeout(async () => {
    try {
      // Three attack models run locally: the neural network, word & name lists, and the 1M leaked-password
      // corpus. The one that needs the FEWEST guesses decides the guesses and crack time shown.
      const g = await window.PrivPassGuess.estimate(password, typeof contexts === 'function' ? contexts() : []);
      if (seq !== neuralSeq || !g) return;
      analysis.neural = { log10Guesses: g.log10Guesses, score: g.score, driver: g.driver };
      const fmt = (x) => (x == null ? '—' : `10^${Number(x).toFixed(1)}`);
      setText('nn-guesses', fmt(g.log10Guesses));
      setText('nn-score', `${g.score}`); setText('nn-rules', `${analysis.score}`);
      setText('nn-time', g.crackTime);
      $('#nn-bar').style.width = `${g.score}%`; $('#nn-rules-bar').style.width = `${analysis.score}%`;
      const words = g.structure?.words?.length ? ` (“${g.structure.words.slice(0, 3).join('” + “')}”)` : '';
      const models = `Neural ${fmt(g.neural?.log10Guesses)} · word & name lists ${fmt(g.structure?.log10Guesses)}${words} · leaked list ${g.inCorpus ? 'FOUND' : 'not found'}.`;
      if (!analysis.generated) {
        // Conservative combination: whichever model finds the password easier to guess wins.
        const combined = Math.min(analysis.score, g.score);
        const driver = g.score < analysis.score ? g.driver : 'pattern rules';
        $('#pw-score').textContent = `${combined} / 100`; $('#pw-bar').style.width = `${combined}%`;
        $('#pw-label').textContent = scoreLabel(combined);
        setText('nn-headline', g.log10Guesses < 9 ? 'Looks like passwords attackers try early.' : g.log10Guesses < 14 ? `Guessable by a determined offline attacker (${g.driver}).` : 'None of the attack models finds this quickly.');
        setText('nn-sub', `${models} Combined score ${combined}/100 — the most conservative model (${driver}) wins.`);
      } else {
        setText('nn-headline', 'Generated secret: construction entropy applies.');
        setText('nn-sub', `For CSPRNG output the exact construction entropy is more precise than any model estimate. ${models}`);
      }
    } catch { setText('nn-headline', 'Neural model unavailable — rules-only estimate shown.'); }
  }, 140);
}
function resetNeuralPanel() {
  ['nn-guesses', 'nn-score', 'nn-rules', 'nn-time'].forEach((id) => setText(id, '—'));
  if ($('#nn-bar')) $('#nn-bar').style.width = '0%'; if ($('#nn-rules-bar')) $('#nn-rules-bar').style.width = '0%';
  setText('nn-headline', 'Type a password to get a neural guess estimate.');
  $('#ai-coach')?.classList.add('hidden');
}

function coachFlags(analysis, password) {
  const f = analysis.flags || {};
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((rx) => rx.test(password)).length;
  return {
    length: analysis.length, score: Math.min(analysis.score, analysis.neural?.score ?? 100), label: scoreLabel(Math.min(analysis.score, analysis.neural?.score ?? 100)),
    log10_guesses: Math.max(0, Number(analysis.log10Guesses) || 0), neural_log10: analysis.neural ? analysis.neural.log10Guesses : null, char_classes: classes,
    flags: { common: COMMON.has(normalizePassword(password).toLowerCase()), identity_like: !!(f.identityLike || analysis.identityHits?.length), dictionary_like: !!f.dictionaryLike, year: !!f.date,
      keyboard: !!f.keyboard, sequence: !!f.sequence, repeat_substring: !!(f.repeated || f.repeatedWord), digit_only: !!f.digitOnly,
      breached: state.hibp?.status === 'breached', generated: !!analysis.generated },
  };
}
$('#ai-coach-btn')?.addEventListener('click', async () => {
  const password = $('#pw-input')?.value || '';
  if (!password) { toast('Type a password first.'); return; }
  const box = $('#ai-coach'); box.classList.remove('hidden'); box.innerHTML = '<div class="ai-loading">Asking the coach…</div>';
  try {
    const flags = coachFlags(currentAnalysis, password);
    const r = await api('/api/ai/password-coach', { method: 'POST', body: JSON.stringify(flags) });
    box.innerHTML = `<div class="ai-head"><b>${escapeHtml(r.summary || '')}</b><span class="mode-chip">${escapeHtml(r.mode)}</span></div>
      <div class="ai-cols"><div><div class="detail-label">WHY</div><ul>${(r.why || []).map((x) => `<li>${escapeHtml(x)}</li>`).join('')}</ul></div>
      <div><div class="detail-label">DO THIS</div><ul>${(r.advice || []).map((x) => `<li>${escapeHtml(x)}</li>`).join('')}</ul></div></div>
      <details class="ai-sent"><summary>What the AI received (no password)</summary><pre>${escapeHtml(JSON.stringify(r.sent, null, 2))}</pre></details>`;
  } catch (error) { box.innerHTML = `<div class="auth-status show bad">${escapeHtml(error.message)}</div>`; }
});
function analyzePasswordModel(password, generated = false) {
  return analyzePasswordCore(password, contexts(), generated);
}

// A new password invalidates any earlier breach result shown for the previous one.
function resetBreachEvidence() {
  state.hibp = null;
  const lc = $('#local-corpus'); if (lc) { lc.textContent = '—'; lc.className = ''; }
  const pf = $('#hibp-prefix'); if (pf) pf.textContent = 'WAITING';
}
$('#pw-input')?.addEventListener('input', () => {
  clearTimeout(state.analyzeTimer);
  resetBreachEvidence();
  state.analyzeTimer = setTimeout(refreshPasswordAnalysis, 60);
});
$('#pw-reveal')?.addEventListener('click', () => { $('#pw-input').type = $('#pw-input').type === 'password' ? 'text' : 'password'; });
$('#analyze-password')?.addEventListener('click', () => { resetBreachEvidence(); refreshPasswordAnalysis(); toast('Password analyzed locally — no network request was made.'); });
$('#clear-password')?.addEventListener('click', () => {
  $('#pw-input').value = '';
  resetBreachEvidence();
  $('#pw-result').className = 'result info';
  $('#pw-result').textContent = 'Waiting for a password check.';
  refreshPasswordAnalysis();
});
$('#pw-context-name')?.addEventListener('input', refreshPasswordAnalysis);
$('#pw-context-org')?.addEventListener('input', refreshPasswordAnalysis);

function generateSecurePassphrase(wordCount = 8) {
  const words = ['amber','anchor','atlas','aurora','beacon','birch','canyon','cedar','cobalt','comet','copper','coral','dawn','delta','ember','falcon','forest','galaxy','harbor','hazel','jasmine','lantern','maple','meadow','meridian','meteor','midnight','mint','nebula','nova','ocean','onyx','orbit','otter','pine','quartz','rain','river','rocket','saffron','signal','silver','solstice','sparrow','summit','thunder','topaz','velvet','violet','willow','winter','zenith','apple','apricot','bamboo','breeze','brook','button','cabin','cactus','camera','candle','caramel','castle','cello','cherry','cinder','circle','clover','cloud','coffee','coral','cotton','crane','cricket','crystal','current','daisy','denim','desert','diamond','drift','eagle','echo','elm','falcon','feather','fig','flame','flock','flower','fog','fountain','frost','garden','glacier','glow','granite','grape','grove','hammer','hearth','horizon','island','ivory','jade','jungle','kettle','kiwi','lake','lemon','linen','lily','lunar','marble','matrix','meadow','melon','merlot','mirror','mocha','morning','moss','mountain','nectar','olive','orchid','panda','paper','peach','pearl','pepper','phoenix','planet','plum','pocket','polar','pond','prairie','pumpkin','raven','reef','ripple','robin','sable','sail','sage','satin','scout','shadow','shell','shore','sky','slate','snow','solar','spice','spindle','spruce','star','stone','storm','stream','sunrise','sunset','tangerine','tempo','thistle','tiger','timber','toast','trail','tulip','valley','vanilla','violet','walnut','wave','whale','whisper','wildflower','window','woodland','yellow','zephyr','zinnia','apron','arrow','badge','basket','basil','beetle','berry','blossom','boat','bonfire','branch','bread','bridge','button','cabin','canyon','carriage','cinnamon','compass','cookie','corner','cove','crown','drizzle','feast','fern','flute','fossil','frame','gem','ginger','harvest','honey','jacket','jigsaw','kernel','kite','ladder','leopard','lighthouse','linen','locket','lotus','magnet','meadow','moon','mosaic','napkin','needle','orange','pebble','picnic','pillow','planet','plaza','plover','poppy','postcard','puzzle','ribbon','sandal','satellite','scoop','seashell','sketch','spoon','starlight','sugar','sweater','tulip','vacation','whistle','window','wizard','yarn','yonder' ];
  const wordList = words.slice(0, 256);
  const values = crypto.getRandomValues(new Uint32Array(wordCount));
  return [...values].map((value) => wordList[value % wordList.length]).join('-');
}

function updateGeneratorLengthLabel() {
  const input = $('#generator-length');
  const label = $('#generator-length-value');
  const mode = $('#generator-mode')?.value || 'random';
  if (!input || !label) return;
  label.textContent = mode === 'passphrase' ? `${Math.max(4, Math.min(8, Math.round(Number(input.value) / 8)))} words` : `${input.value} chars`;
}

function updatePrivacyPreview(password) {
  const prefixEl = $('#hibp-prefix');
  const resultEl = $('#pw-result');
  const empty = !password;
  if (empty) {
    if (prefixEl) prefixEl.textContent = 'WAITING';
    return;
  }
  if (resultEl && !state.hibp) {
    resultEl.className = 'result info';
    resultEl.textContent = 'Ready — analysis is local. Nothing is sent until you press “Check with HIBP”.';
  }
}

function generateSecureSecret(length = 32) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=?';
  const result = [];
  const limit = Math.floor(0x100000000 / alphabet.length) * alphabet.length;
  const buffer = new Uint32Array(Math.max(128, length * 2));
  while (result.length < length) {
    crypto.getRandomValues(buffer);
    for (const value of buffer) {
      if (value >= limit) continue;
      result.push(alphabet[value % alphabet.length]);
      if (result.length === length) break;
    }
  }
  return result.join('');
}

$('#generate-pass')?.addEventListener('click', () => {
  const length = Number($('#generator-length')?.value || 32);
  const mode = $('#generator-mode')?.value || 'random';
  const secret = mode === 'passphrase' ? generateSecurePassphrase(Math.max(6, Math.min(8, Math.round(length / 8)))) : generateSecureSecret(length);
  $('#pw-input').value = secret;
  $('#pw-input').type = 'text';
  clearTimeout(state.analyzeTimer);
  resetBreachEvidence();
  currentAnalysis = analyzePasswordCore(secret, contexts(), true);
  updatePasswordUI(currentAnalysis);
  updatePrivacyPreview(secret);
  scheduleNeural(secret, currentAnalysis);
  $('#ai-coach')?.classList.add('hidden');
  toast(mode === 'passphrase' ? 'Secure passphrase generated locally.' : `${length}-character Web Crypto secret generated locally with rejection sampling.`);
});

$('#generator-length')?.addEventListener('input', updateGeneratorLengthLabel);
$('#generator-mode')?.addEventListener('change', () => {
  if ($('#generator-mode').value === 'passphrase') $('#generator-length').value = '64';
  else if ($('#generator-length').value > '48') $('#generator-length').value = '32';
  updateGeneratorLengthLabel();
});
$('#copy-pass')?.addEventListener('click', async () => {
  const value = $('#pw-input')?.value || '';
  if (!value) { toast('Generate or enter a secret first.'); return; }
  try { await navigator.clipboard.writeText(value); toast('Secret copied. PrivPass never stores the clipboard value.'); }
  catch { toast('Clipboard permission was not available; copy it manually.'); }
});
updateGeneratorLengthLabel();


const OFFLINE_DEMO = {
  // Synthetic offline fixture for demos without internet: a handful of passwords that are
  // famously present in HIBP. Results from this fixture are labelled "offline-demo" and can
  // NEVER satisfy the signup/reset gate, which requires a live verification.
  '5BAA6': { '1E4C9B93F3F0682250B6CF8331B7EE68FD8': 0 }, // password
  '7C4A8': { 'D09CA3762AF61E59520943DC26494F8941B': 0 }, // 123456
  'CBFDA': { 'C6008F9CAB4083784CBD1874F76618D2A97': 0 }, // password123
  'B1B37': { '73A05C0ED0176787A4F1574FF0075F7521E': 0 }, // qwerty
  'EE8D8': { '728F435FD550F83852AABAB5234CE1DA528': 0 }, // iloveyou
  '70CCD': { '9007338D6D81DD3B6271621B9CF9A97EA00': 0 }, // Password1
  'B7A87': { '5FC1EA228B9061041B7CEC4BD3C52AB3CE3': 0 }, // letmein
  'E35BE': { 'CE6C5E6E0E86CA51D0440E92282A9D6AC8A': 0 }, // welcome1
  '8D6E3': { '4F987851AA599257D3831A1AF040886842F': 0 }, // sunshine
  '2D27B': { '62C597EC858F6E7B54E7E58525E6A95E6D8': 0 }, // football
  'F865B': { '53623B121FD34EE5426C792E5C33AF8C227': 0 }, // admin123
  'AB87D': { '24BDC7452E55738DEB5F868E1F16DEA5ACE': 0 }, // monkey
  'AF897': { '8B1797B72ACFFF9595A5A2A373EC3D9106D': 0 }, // dragon
};

async function lookupHibp(password) {
  const digest = await sha1Hex(normalizePassword(password));
  const prefix = digest.slice(0, 5).toUpperCase();
  const suffix = digest.slice(5).toUpperCase();
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
    if (!response.ok) throw new Error(`HIBP HTTP ${response.status}`);
    const text = await response.text();
    let breached = false;
    let count = 0;
    for (const line of text.split(/\r?\n/)) {
      const [returnedSuffix, returnedCount] = line.trim().split(':');
      if (returnedSuffix?.toUpperCase() === suffix) {
        breached = true;
        count = Number(returnedCount) || 0;
        break;
      }
    }
    return { status: breached ? 'breached' : 'safe', mode: 'live', prefix, breached, count };
  } catch (error) {
    const demoCount = OFFLINE_DEMO[prefix]?.[suffix];
    if (demoCount !== undefined) return { status: 'breached', mode: 'offline-demo', prefix, breached: true, count: demoCount };
    return { status: 'unavailable', mode: 'unavailable', prefix, breached: false, count: 0, error: String(error?.message || error) };
  }
}

async function hibpCheck() {
  const password = $('#pw-input').value;
  if (!password) { toast('Enter a password first.'); refreshPasswordAnalysis(); return; }
  const analysis = analyzePasswordModel(password, false);
  if (analysis.length < 10) {
    $('#pw-result').className = 'result bad';
    $('#pw-result').textContent = 'Test blocked — minimum 10 characters is required for the analysis lab. Account creation still requires 15+.';
    return;
  }
  $('#pw-result').className = 'result info';
  $('#pw-result').textContent = 'Checking the HIBP range. Only a five-character SHA-1 prefix leaves the browser…';
  const [result, local] = await Promise.all([lookupHibp(password), window.PrivPassBloom ? window.PrivPassBloom.check(normalizePassword(password)).catch(() => null) : null]);
  state.hibp = result;
  const lc = $('#local-corpus'); if (lc) { lc.textContent = local === null ? 'N/A' : local ? 'FOUND' : 'NOT FOUND'; lc.className = local ? 'bad' : 'good'; }
  $('#hibp-prefix').textContent = result.prefix;
  if (result.status === 'breached') {
    $('#pw-result').className = 'result bad';
    $('#pw-result').textContent = `BLOCKED — password appears in ${result.mode === 'offline-demo' ? 'the offline demo breach fixture' : 'known breach data'}${result.count ? ` (${result.count.toLocaleString()} ${result.mode === 'offline-demo' ? 'demo occurrences' : 'observed occurrences'})` : ''}.`;
    $('#pw-headline').textContent = 'Breach evidence overrides every other strength estimate.';
  } else if (result.status === 'safe') {
    $('#pw-result').className = 'result good';
    $('#pw-result').textContent = `No exact match found in the returned HIBP range. Live response verified.`;
  } else {
    $('#pw-result').className = 'result warn';
    $('#pw-result').textContent = 'HIBP is temporarily unavailable. Breach status is UNVERIFIED — do not treat this password as safe for an account decision.';
  }
  try { await api('/api/password-event', { method: 'POST', body: JSON.stringify({ event_type: 'hibp_check', breached: result.status === 'breached', score: analysis.score, score_label: analysis.label, guess_log10: analysis.log10Guesses }) }); } catch {}
}
$('#hibp-check')?.addEventListener('click', hibpCheck);

const presetPasswords = {
  longpredictable: 'aaaasfiefifosdnofsdfn',
  identityreuse: 'divy1023divy1032',
  numeric: '3492847592039485720',
  humanrandom: 'asfajfbjadbfiwebfiwefiewb',
  passphrase: 'river lantern copper orbit',
};
$$('.scenario').forEach((button) => button.addEventListener('click', () => {
  const value = presetPasswords[button.dataset.preset];
  $('#pw-input').value = value;
  $('#pw-input').type = 'text';
  resetBreachEvidence();
  refreshPasswordAnalysis();
  toast(`Loaded ${button.querySelector('b')?.textContent || 'scenario'}.`);
}));

refreshPasswordAnalysis();

const benchmarkCases = [
  ['Long but predictable', presetPasswords.longpredictable, 'Expected weak'],
  ['Identity + numbers', presetPasswords.identityreuse, 'Expected fair / context risk'],
  ['Numeric-only', presetPasswords.numeric, 'Expected fair / highly guessable'],
  ['Random-looking human text', presetPasswords.humanrandom, 'Expected strong-ish, not perfect'],
  ['Long passphrase', presetPasswords.passphrase, 'Expected strong'],
];

$('#run-benchmark')?.addEventListener('click', () => {
  const table = $('#benchmark-results');
  if (!table) return;
  table.innerHTML = benchmarkCases.map(([name, value, target]) => {
    const result = analyzePasswordCore(value, [], false);
    return `<tr><td>${escapeHtml(name)}</td><td><code>${escapeHtml(value)}</code></td><td>${result.score}/100</td><td>${escapeHtml(result.label)}</td><td>${escapeHtml(result.verdict)}</td><td>${escapeHtml(result.reasons[0] || target)}</td></tr>`;
  }).join('');
  $('#benchmark-panel')?.classList.add('visible');
  toast('Five real-life password cases analyzed locally.');
});

function setSecretScanBusy(busy, filename = '') {
  state.scanBusy = busy;
  const drop = $('#dropzone');
  const browse = $('#browse-repo');
  const judge = $('#judge-scan');
  const list = $('#findings-list');
  if (drop) drop.classList.toggle('scanning', busy);
  if (browse) browse.disabled = busy;
  if (judge) judge.disabled = busy;
  if (busy && list) {
    list.innerHTML = `<div class="scan-loading" role="status"><span class="scan-spinner" aria-hidden="true"></span><div><b>Scanning repository${filename ? ` · ${escapeHtml(filename)}` : ''}…</b><small>Inspecting text files and evaluating provider patterns, context, entropy and validity.</small></div></div>`;
  }
}

async function scanFile(file) {
  setSecretScanBusy(true, file.name);
  const form = new FormData();
  form.append('file', file);
  try {
    const data = await api('/api/scans/upload', { method: 'POST', body: form });
    state.lastScanSource = null;
    state.secretFindingLimit = 40;
    renderFindings(data.findings || []);
    toast(`Scan complete: ${data.findings?.length || 0} findings across ${data.files || 0} files${data.history_only ? ` — ${data.history_only} only in git history` : ''}${data.risky_code ? ` — ${data.risky_code} risky code patterns` : ''}.`);
    loadExposureGraph();
    loadIncidents();
  } catch (error) {
    const list = $('#findings-list');
    if (list) list.innerHTML = `<div class="scan-loading error-state" role="alert"><div><b>Scan failed</b><small>${escapeHtml(error.message)}</small></div></div>`;
    toast(error.message);
  } finally {
    setSecretScanBusy(false);
  }
}
$('#browse-repo')?.addEventListener('click', () => $('#repo-file').click());
$('#repo-file')?.addEventListener('change', (event) => event.target.files[0] && scanFile(event.target.files[0]));
const dropzone = $('#dropzone');
if (dropzone) {
  ['dragover','dragleave'].forEach((eventName) => dropzone.addEventListener(eventName, (event) => { event.preventDefault(); dropzone.classList.toggle('drag', eventName === 'dragover'); }));
  dropzone.addEventListener('drop', (event) => { event.preventDefault(); dropzone.classList.remove('drag'); const file = event.dataTransfer.files[0]; if (file) scanFile(file); });
}

async function transitionFinding(id, status) {
  try {
    const result = await api(`/api/findings/${encodeURIComponent(id)}/transition`, { method: 'POST', body: JSON.stringify({ status }) });
    const target = state.secretFindings.find((finding) => finding.id === id);
    if (target) target.status = result.status || status;
    renderFindings(state.secretFindings, { preserveLimit: true });
    toast(result.unchanged ? `Finding is already ${result.status}.` : `Finding moved to ${result.status}.`);
    loadExposureGraph();
    loadIncidents();
  } catch (error) { toast(error.message); }
}

function findingWhy(type) {
  const map = {
    'AWS access key': 'Provider-specific credential detected. An exposed AWS key can grant access to cloud resources depending on its permissions.',
    'AWS temporary access key': 'A temporary cloud credential matched the provider format and may expose scoped AWS resources until it expires or is revoked.',
    'GitHub token': 'Source-control credential detected. An exposed token may grant repository or automation access according to its scopes.',
    'GitLab token': 'GitLab credential format detected. Treat it as exposed until revoked or rotated.',
    'Stripe secret key': 'Payment credential detected. A leaked Stripe key can expose payment-platform operations according to its permissions.',
    'Slack token': 'Messaging/platform token detected. Exposed tokens can provide access to workspace resources according to their scope.',
    'Google API key': 'Google API credential pattern detected. Exposure may enable API use subject to project restrictions and quotas.',
    'OpenAI API key': 'AI service credential detected. An exposed key can enable unauthorized API usage subject to account controls.',
    'SendGrid API key': 'Email-service credential detected. Exposure may allow unauthorized mail/API operations according to its permissions.',
    'JWT': 'Bearer-token structure detected. A token embedded in source can remain usable until it expires or is revoked.',
    'Connection string': 'Connection material may contain usernames, passwords or host information that should not live in source code.',
    'Private key': 'Private key material can enable impersonation or decryption depending on the key type and trust relationship.',
    'Generic secret assignment': 'A contextual secret-like assignment was detected and escalated using entropy and surrounding code evidence.',
  };
  return map[type] || 'Secret-like material was detected using pattern and contextual analysis.';
}

function findingNextStep(type) {
  if (type === 'Private key') return 'Revoke/replace the key, remove it from source, then verify downstream certificates or trust relationships.';
  if (type === 'JWT') return 'Revoke or expire the token, remove it from source/history, and issue a replacement through the normal identity flow.';
  if (type === 'Connection string') return 'Move credentials to an approved secret manager or environment variable, rotate the exposed credential, then rescan.';
  return 'Revoke or rotate the credential first, remove the exposed value, inspect Git history, then rescan and verify the replacement.';
}

function findingEvidenceClass(value) {
  const text = String(value || '').toLowerCase();
  if (text.includes('valid') || text.includes('marker') || text === 'format_match') return 'evidence-good';
  if (text.includes('invalid') || text.includes('unknown')) return 'evidence-warn';
  return 'evidence-neutral';
}

function filteredFindings() {
  const search = ($('#finding-search')?.value || '').trim().toLowerCase();
  const severity = $('#finding-severity')?.value || 'ALL';
  const status = $('#finding-status')?.value || 'ALL';
  return state.secretFindings.filter((finding) => {
    if (severity !== 'ALL' && finding.severity !== severity) return false;
    if (status !== 'ALL' && (finding.status || 'DETECTED') !== status) return false;
    if (!search) return true;
    const haystack = `${finding.type || ''} ${finding.file || ''} ${finding.reason || ''} ${finding.validity || ''}`.toLowerCase();
    return haystack.includes(search);
  });
}

function renderDiff(diff) {
  return diff.split('\n').map((l) => `<span class="${l.startsWith('+') && !l.startsWith('+++') ? 'add' : l.startsWith('-') && !l.startsWith('---') ? 'del' : l.startsWith('@@') ? 'hunk' : ''}">${escapeHtml(l)}</span>`).join('\n');
}
async function aiFix(id, button) {
  const box = $(`#ai-fix-${CSS.escape(id)}`); if (!box) return;
  box.classList.remove('hidden'); box.innerHTML = '<div class="ai-loading">Generating a fix from the masked context…</div>';
  setBusy(button, true, 'Working…');
  try {
    const r = await api(`/api/ai/remediate/${encodeURIComponent(id)}`, { method: 'POST', body: JSON.stringify({}) });
    const list = (items) => (items || []).map((x) => `<li>${escapeHtml(x)}</li>`).join('');
    box.innerHTML = `<div class="ai-head"><b>✦ AI remediation</b><span class="mode-chip">${escapeHtml(r.mode)}</span></div>
      <p>${escapeHtml(r.summary || '')}</p>
      ${r.patch ? `<div class="detail-label">PATCH</div><pre class="diff">${renderDiff(r.patch)}</pre><button class="mini-action copy-patch" type="button">Copy patch</button>` : ''}
      ${r.notes?.length ? `<ul class="ai-notes">${list(r.notes)}</ul>` : ''}
      <div class="ai-cols"><div><div class="detail-label">ROTATE${r.provider ? ` AT ${escapeHtml(r.provider.toUpperCase())}` : ''}</div><ol>${list(r.runbook)}</ol>${r.console ? `<a class="link-btn" href="${escapeHtml(r.console)}" rel="noopener" target="_blank">Open ${escapeHtml(r.provider)} console ↗</a>` : ''}</div>
      <div><div class="detail-label">VERIFY</div><ol>${list(r.verify)}</ol></div></div>
      ${r.history_cleanup?.length ? `<div class="detail-label">HISTORY CLEAN-UP (AFTER ROTATING)</div><pre class="cmd">${escapeHtml(r.history_cleanup.join('\n'))}</pre>` : ''}
      <div class="ai-fix-actions">${state.lastScanSource ? `<button class="btn primary open-pr" type="button">⤴ Open fix pull request on GitHub</button>` : ''}${r.provider ? `<button class="btn secondary to-vault" type="button">🔒 Store the new ${escapeHtml(r.provider)} key in my vault</button>` : ''}</div>
      <div class="pr-result"></div>
      <details class="ai-sent"><summary>What the AI received</summary><pre>${escapeHtml(JSON.stringify(r.ai_input, null, 2))}</pre></details>`;
    box.querySelector('.open-pr')?.addEventListener('click', (e) => openFixPr(id, e.currentTarget, box.querySelector('.pr-result')));
    box.querySelector('.to-vault')?.addEventListener('click', () => storeRotatedInVault(r.provider, r.ai_input));
    box.querySelector('.copy-patch')?.addEventListener('click', async () => { try { await navigator.clipboard.writeText(r.patch); toast('Patch copied.'); } catch { toast('Copy failed - select the text manually.'); } });
  } catch (error) { box.innerHTML = `<div class="auth-status show bad">${escapeHtml(error.message)}</div>`; }
  finally { setBusy(button, false); }
}
$('#ai-triage')?.addEventListener('click', async () => {
  const btn = $('#ai-triage'); setBusy(btn, true, 'Triaging…');
  try {
    const r = await api('/api/ai/triage', { method: 'POST', body: JSON.stringify({}) });
    const byId = Object.fromEntries(r.triaged.map((t) => [t.id, t]));
    state.secretFindings.forEach((f) => { if (byId[f.id]) { f.ai_verdict = byId[f.id].verdict; f.ai_reason = `${byId[f.id].explanation} [${byId[f.id].mode}]`; } });
    renderFindings(state.secretFindings, { preserveLimit: true });
    toast(r.triaged.length ? `AI triaged ${r.triaged.length} grey-zone finding(s) (ML ${Math.round(r.grey_zone[0] * 100)}–${Math.round(r.grey_zone[1] * 100)}%).` : 'No grey-zone findings — the ML model is confident about every finding in this scan.');
  } catch (error) { toast(error.message); }
  finally { setBusy(btn, false); }
});

function renderFindings(findings, options = {}) {
  const list = $('#findings-list');
  if (!list) return;
  state.secretFindings = Array.isArray(findings) ? findings : [];
  if (!options.preserveLimit) state.secretFindingLimit = 40;
  let critical = 0, high = 0, medium = 0;
  state.secretFindings.forEach((finding) => { if (finding.severity === 'CRITICAL') critical += 1; else if (finding.severity === 'HIGH') high += 1; else medium += 1; });
  $('#crit-count').textContent = critical;
  $('#high-count').textContent = high;
  $('#med-count').textContent = medium;
  $('#conf-count').textContent = state.secretFindings.length ? `${Math.round(state.secretFindings.reduce((sum, item) => sum + Number(item.confidence || 0), 0) / state.secretFindings.length * 100)}%` : '—';
  const filtered = filteredFindings();
  const visible = filtered.slice(0, Math.max(1, state.secretFindingLimit));
  const remaining = Math.max(0, filtered.length - visible.length);
  $('#finding-meta').textContent = state.secretFindings.length
    ? `${visible.length} shown • ${state.secretFindings.length} total${remaining ? ` • ${remaining} more available` : ''}`
    : 'No findings';
  if (!visible.length) {
    list.innerHTML = state.secretFindings.length
      ? '<div class="empty-state">No findings match the current filters.</div>'
      : '<div class="empty-state">Run the Judge Demo or upload the included demo ZIP.</div>';
    return;
  }
  list.innerHTML = visible.map((finding, index) => {
    const confidence = Math.round(Number(finding.confidence || 0) * 100);
    const entropy = Number(finding.entropy || 0).toFixed(2);
    const severity = escapeHtml(finding.severity || 'MEDIUM');
    const status = escapeHtml(finding.status || 'DETECTED');
    const validity = escapeHtml(finding.validity || 'UNKNOWN');
    const preview = escapeHtml(finding.preview || 'redacted');
    const reason = escapeHtml(finding.reason || 'Contextual secret-like material detected.');
    const type = escapeHtml(finding.type || 'Secret-like material');
    const file = escapeHtml(finding.file || 'unknown file');
    const line = escapeHtml(finding.line ?? '—');
    const isCode = finding.kind === 'code';
    const historyOnly = finding.in_head === false;
    const why = escapeHtml(isCode ? 'A risky code pattern matched a Secure Code Checker rule. It is not a secret, but it is a common path to injection, MITM or code execution.' : findingWhy(finding.type));
    const next = escapeHtml(isCode ? (finding.reason || '').replace(/^Risky code pattern; /, '') : historyOnly
      ? 'This value was deleted from HEAD but still lives in git history (every clone and fork has it). Rotate the credential at the provider first; purging history is optional hygiene, not remediation.'
      : findingNextStep(finding.type));
    const commitLine = finding.commit ? `introduced in <code>${escapeHtml(String(finding.commit).slice(0, 10))}</code> by ${escapeHtml(finding.author || 'unknown')} on ${escapeHtml(String(finding.commit_date || '').slice(0, 10))}${finding.commits_seen > 1 ? ` · in ${finding.commits_seen} commits` : ''}` : '';
    const context = /test|doc|example|fixture/i.test(String(finding.reason || '') + String(finding.file || ''))
      ? 'Test/example context was detected; confidence may have been reduced.'
      : 'Source context currently provides no test/documentation reduction.';
    const contextEscaped = escapeHtml(context);
    const isBlocking = ['CRITICAL','HIGH'].includes(finding.severity) && (isCode || confidence >= 80);
    const blockPill = (isBlocking ? '<span class="finding-chip block">CI BLOCKING</span>' : '<span class="finding-chip review">REVIEW</span>')
      + (historyOnly ? '<span class="finding-chip history">GIT HISTORY ONLY</span>' : '')
      + (isCode ? '<span class="finding-chip code">RISKY CODE</span>' : '')
      + (typeof slaChip === 'function' ? slaChip(finding.sla, finding.status) : '')
      + (finding.ml_probability != null ? `<span class="finding-chip ml" title="SecretGuard ML classifier">ML ${Math.round(finding.ml_probability * 100)}%</span>` : '')
      + (finding.ai_verdict ? `<span class="finding-chip verdict ${escapeHtml(finding.ai_verdict)}">${escapeHtml(finding.ai_verdict.replace(/_/g, ' '))}</span>` : '');
    const mlBlock = finding.ml_probability != null
      ? `<div class="ml-explain"><div class="detail-label">WHY THE ML MODEL SCORED IT ${Math.round(finding.ml_probability * 100)}%</div><div class="ml-reasons">${(finding.ml_reasons || []).map((r) => `<span class="${r.startsWith('+') ? 'up' : 'down'}">${escapeHtml(r)}</span>`).join('') || '<span>No dominant feature</span>'}</div>${finding.ai_reason ? `<p class="ai-verdict-text"><b>AI triage:</b> ${escapeHtml(finding.ai_reason)}</p>` : ''}</div>` : (finding.ai_reason ? `<p class="ai-verdict-text"><b>AI triage:</b> ${escapeHtml(finding.ai_reason)}</p>` : '');
    const contextBlock = finding.context ? `<div class="masked-context"><div class="detail-label">MASKED CONTEXT (the only code the AI can see)</div><pre>${escapeHtml(finding.context)}</pre></div>` : '';
    return `<article class="finding-card${index === 0 ? ' first-card' : ''}" data-finding-id="${escapeHtml(finding.id || '')}">
      <details class="finding-details">
        <summary class="finding-summary">
          <span class="finding-summary-main"><span class="finding-type-line"><b>${type}</b><span class="finding-file">${file}:${line}</span></span><span class="finding-subline">${isCode ? `rule match • <code>${preview}</code>` : `confidence ${confidence}% • entropy ${entropy} • ${validity} • ${preview}`}</span>${commitLine ? `<span class="finding-subline commit-line">${commitLine}</span>` : ''}</span>
          <span class="finding-summary-side">${blockPill}<span class="sev ${severity}">${severity}</span><span class="finding-chevron" aria-hidden="true">⌄</span></span>
        </summary>
        <div class="finding-detail-body">
          <div class="finding-evidence-grid">
            <div><span>Confidence</span><b>${confidence}%</b><i><em style="width:${Math.max(4, Math.min(100, confidence))}%"></em></i></div>
            <div><span>Entropy</span><b>${entropy}</b><small>Higher entropy can strengthen generic-secret confidence.</small></div>
            <div><span>Validity</span><b class="${findingEvidenceClass(validity)}">${validity}</b><small>${validity.includes('LIVE') || validity.includes('REJECTED') ? 'Live provider verification (opt-in, CI).' : 'Offline structural/provider-format validation.'}</small></div>
            <div><span>Decision gate</span><b class="${isBlocking ? 'evidence-danger' : 'evidence-neutral'}">${isBlocking ? 'BLOCK' : 'REVIEW'}</b><small>Based on severity and confidence threshold.</small></div>
          </div>
          <div class="finding-detail-grid">
            <section><div class="detail-label">WHY THIS WAS DETECTED</div><p>${why}</p><div class="detail-context">${contextEscaped}</div></section>
            <section><div class="detail-label">DETECTED EVIDENCE</div><dl><div><dt>File</dt><dd>${file}</dd></div><div><dt>Line</dt><dd>${line}</dd></div><div><dt>Redacted</dt><dd><code>${preview}</code></dd></div><div><dt>Reason</dt><dd>${reason}</dd></div></dl></section>
          </div>
          ${mlBlock}${contextBlock}
          <div class="finding-remediation"><div><div class="detail-label">RECOMMENDED RESPONSE</div><p>${next}</p><button class="btn secondary ai-fix-btn" data-fix="${escapeHtml(finding.id || '')}" type="button">✦ AI fix: patch + rotation runbook</button></div><div class="finding-lifecycle"><span class="status-chip ${status.toLowerCase()}">${status}</span>${status === 'DETECTED' ? '<button class="mini-action"' + ` data-id="${escapeHtml(finding.id || '')}" data-status="TRIAGED">Triage →</button>` : ''}${status === 'TRIAGED' ? '<button class="mini-action"' + ` data-id="${escapeHtml(finding.id || '')}" data-status="CONTAINED">Contain →</button>` : ''}${status === 'CONTAINED' ? '<button class="mini-action"' + ` data-id="${escapeHtml(finding.id || '')}" data-status="ROTATED">Rotate →</button>` : ''}${status === 'ROTATED' ? '<button class="mini-action"' + ` data-id="${escapeHtml(finding.id || '')}" data-status="VERIFIED">Verify ✓</button>` : ''}${status === 'VERIFIED' ? '<span class="lifecycle-complete">✓ Verified</span>' : ''}</div></div>
          <div class="ai-fix hidden" id="ai-fix-${escapeHtml(finding.id || '')}"></div>
        </div>
      </details>
    </article>`;
  }).join('');
  if (remaining) list.insertAdjacentHTML('beforeend', `<button type="button" class="show-more-findings" id="show-more-findings">Show ${Math.min(40, remaining)} more findings <span>↓</span></button>`);
  $$('.mini-action').forEach((button) => button.addEventListener('click', (event) => { event.stopPropagation(); transitionFinding(button.dataset.id, button.dataset.status); }));
  $$('.ai-fix-btn').forEach((button) => button.addEventListener('click', (event) => { event.stopPropagation(); aiFix(button.dataset.fix, button); }));
  $('#show-more-findings')?.addEventListener('click', () => { state.secretFindingLimit += 40; renderFindings(state.secretFindings, { preserveLimit: true }); });
}

['input', 'change'].forEach((eventName) => {
  $('#finding-search')?.addEventListener(eventName, () => renderFindings(state.secretFindings));
  $('#finding-severity')?.addEventListener(eventName, () => renderFindings(state.secretFindings));
  $('#finding-status')?.addEventListener(eventName, () => renderFindings(state.secretFindings));
});
$('#finding-clear-filters')?.addEventListener('click', () => { if ($('#finding-search')) $('#finding-search').value=''; if ($('#finding-severity')) $('#finding-severity').value='ALL'; if ($('#finding-status')) $('#finding-status').value='ALL'; renderFindings(state.secretFindings); });

$('#judge-scan')?.addEventListener('click', async () => {
  try {
    const data = await api('/api/judge/demo-scan', { method: 'POST' });
    state.secretFindingLimit = 40;
    renderFindings(data.findings || []);
    toast(`Judge demo scanned ${data.files} files and found ${data.findings.length} issues.`);
    loadExposureGraph();
    loadIncidents();
    nav('secrets');
  } catch (error) { toast(`Admin sign-in required: ${error.message}`); }
});

function setText(id, value) {
  const el = $('#' + id); if (el) el.textContent = value ?? '—';
}

function riskClass(value) {
  return ['CRITICAL', 'HIGH', 'ELEVATED'].includes(value) ? 'danger' : value === 'GUARDED' ? 'good' : '';
}

// loadExposureGraph() lives in static/exposure.js (7.1 exposure map).

function incidentAction(status) {
  return ({DETECTED:'TRIAGED', TRIAGED:'CONTAINED', CONTAINED:'ROTATED', ROTATED:'VERIFIED'})[status] || null;
}

function incidentActionLabel(status) {
  return ({DETECTED:'Triage →', TRIAGED:'Contain →', CONTAINED:'Rotate →', ROTATED:'Verify ✓'})[status] || 'Verified ✓';
}

function incidentColumn(title, statuses, incidents) {
  const relevant = incidents.filter((item) => statuses.includes(item.status));
  const visible = relevant.slice(0, 6);
  const cards = visible.map((item) => {
    const status = escapeHtml(item.status);
    const severity = escapeHtml(item.severity || 'MEDIUM');
    const type = escapeHtml(item.type || 'Secret finding');
    const location = `${escapeHtml(item.file || 'unknown file')}:${escapeHtml(item.line ?? '—')}`;
    const action = incidentAction(item.status);
    const actionHtml = action ? `<button class="mini-action incident-transition" data-id="${escapeHtml(item.id)}" data-status="${action}">${incidentActionLabel(item.status)}</button>` : '<span class="lifecycle-complete">✓ Verified</span>';
    return `<article class="incident-card live ${severity.toLowerCase()}"><div class="incident-card-head"><span>${status}</span><b class="severity-chip ${severity}">${severity}</b></div><b>${type}</b><small>${location}</small><small>${escapeHtml(item.repo_name)} · ${item.confidence}% confidence</small>${item.in_head === false ? '<small class="history-flag">Deleted from HEAD · still in git history</small>' : ''}${item.kind === 'code' ? '<small class="history-flag code">Risky code pattern</small>' : ''}${typeof slaText === 'function' ? slaText(item.sla, item.status) : ''}${actionHtml}</article>`;
  }).join('');
  const more = relevant.length > visible.length ? `<div class="incident-more">+ ${relevant.length - visible.length} more in SecretGuard</div>` : '';
  return `<div class="incident-column"><div class="incident-column-head"><h3>${title}</h3><span>${relevant.length}</span></div>${cards || '<div class="incident-empty">No findings in this stage.</div>'}${more}</div>`;
}

async function loadIncidents() {
  try {
    const data = await api('/api/incidents');
    const counts = data.counts || {};
    ['DETECTED','TRIAGED','CONTAINED','ROTATED','VERIFIED'].forEach((status) => setText(`incident-count-${status.toLowerCase()}`, counts[status] || 0));
    const meta = $('#incident-live-meta');
    if (meta) meta.textContent = data.scan ? `Latest scan · ${data.scan.repo_name} · ${data.total} findings` : 'No scan yet';
    const board = $('#incident-board');
    if (!board) return;
    if (!data.total) { board.innerHTML = '<div class="empty-state">Run a SecretGuard scan to create real incidents.</div>'; return; }
    board.innerHTML = [
      incidentColumn('Action needed', ['DETECTED','TRIAGED'], data.incidents || []),
      incidentColumn('Remediation', ['CONTAINED','ROTATED'], data.incidents || []),
      incidentColumn('Verified', ['VERIFIED'], data.incidents || []),
    ].join('');
    $$('.incident-transition').forEach((button) => button.addEventListener('click', (event) => { event.preventDefault(); event.stopPropagation(); transitionFinding(button.dataset.id, button.dataset.status); }));
  } catch (error) {
    const board = $('#incident-board'); if (board) board.innerHTML = `<div class="error-state"><b>Incident data unavailable</b><small>${escapeHtml(error.message)}</small></div>`;
  }
}

async function loadPublic() {
  try {
    const data = await api('/api/analytics/public');
    $('#m-checks').textContent = data.checks;
    $('#m-breach').textContent = `${data.breached_percent}%`;
    $('#m-secrets').textContent = data.secret_findings;
    $('#m-posture').textContent = data.secret_findings > 0 ? 'ELEVATED' : 'HEALTHY';
  } catch {}
}
async function loadFindings() {
  try { renderFindings(await api('/api/findings')); } catch {}
}
async function loadAdmin() {
  try {
    const overview = await api('/api/admin/overview');
    $('#admin-breach').textContent = `${overview.breached_attempt_percent}%`;
    if ($('#admin-gate-sub')) $('#admin-gate-sub').textContent = overview.gate ? `${overview.gate.breached} of ${overview.gate.attempts} signup/reset attempts used a breached password` : 'signup/reset attempts using a breached password';
    renderAuditSummary(overview.account_audit);
    if (typeof renderSla === 'function') renderSla(overview);
    $('#admin-secrets').textContent = overview.secret_findings;
    $('#admin-posture').textContent = `${overview.control_posture}%`;
    $('#admin-avg').textContent = `${overview.average_password_score}`;
    $('#posture-progress').style.width = `${overview.control_posture}%`;
    $('#posture-ring')?.parentElement?.style.setProperty('--angle', `${Math.min(100, Number(overview.breached_attempt_percent) || 0) * 3.6}deg`);
    const users = await api('/api/admin/users');
    $('#user-list').innerHTML = users.map((user) => `<div class="user-row${user.breach_locked ? ' locked' : ''}"><div><b>${escapeHtml(user.email)}${user.breach_locked ? ' <span class="status-chip bad">LOCKED · BREACHED</span>' : ''}</b><span>${escapeHtml(user.role)} • MFA ${user.mfa_enabled ? 'ON' : 'OFF'} • Vault ${user.vault_items || 0} • breach watch: ${user.breach_check_status ? escapeHtml(user.breach_check_status) : 'pending'}</span></div><div class="user-actions">${state.auth?.workspace === 'demo' ? '<span class="status-chip" title="The demo admin cannot suspend or delete accounts">read-only in demo</span>' : user.active ? `<button class="mini-action admin-deactivate" data-user="${escapeHtml(user.id || '')}" data-email="${escapeHtml(user.email)}">Suspend</button>` : '<span class="status-chip">SUSPENDED</span>'}${state.auth?.workspace === 'demo' ? '' : `<button class="mini-action admin-delete" data-user="${escapeHtml(user.id || '')}" data-email="${escapeHtml(user.email)}">Delete</button>`}</div></div>`).join('');
    $$('.admin-deactivate').forEach((button) => button.addEventListener('click', async () => { try { await api(`/api/admin/users/${encodeURIComponent(button.dataset.user)}/deactivate`, { method:'POST', body:JSON.stringify({}) }); toast(`${button.dataset.email} suspended.`); loadAdmin(); } catch (error) { toast(error.message); } }));
    $$('.admin-delete').forEach((button) => button.addEventListener('click', async () => { if (!confirm(`Delete ${button.dataset.email}? This also deletes that user's encrypted vault blobs.`)) return; try { await api(`/api/admin/users/${encodeURIComponent(button.dataset.user)}`, { method:'DELETE', body:JSON.stringify({}) }); toast(`${button.dataset.email} deleted.`); loadAdmin(); } catch (error) { toast(error.message); } }));
    const audit = await api('/api/admin/audit');
    $('#audit-list').innerHTML = audit.map((item) => `<div class="audit-row"><span>${escapeHtml(item.event)}</span><span>${escapeHtml(item.severity)} • ${new Date(item.created_at).toLocaleString()}</span></div>`).join('') || '<div class="empty-state">No events yet.</div>';
  } catch { toast('Sign in as admin to open the Command Center.'); }
}
// ---------------- Test-account breached-password audit ----------------
// Input: a CSV of synthetic test accounts (email,password). Everything below runs in the browser:
// passwords are NFKC-normalized and SHA-1 hashed locally, grouped by 5-char prefix so each prefix is
// fetched once (k-anonymity + Add-Padding), and only aggregate counts are POSTed to the server.
function parseAccountCsv(text) {
  const rows = [];
  let header = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const comma = line.indexOf(',');
    if (comma < 0) continue;
    const first = line.slice(0, comma).trim();
    const rest = line.slice(comma + 1);
    if (!header && /^email$/i.test(first) && /^password$/i.test(rest.trim())) { header = true; continue; }
    rows.push({ email: first, password: rest });
  }
  return rows;
}

function maskEmail(email) {
  const [user, domain] = String(email).split('@');
  if (!domain) return '•••';
  return `${user.slice(0, 2)}${'•'.repeat(Math.max(1, user.length - 2))}@${domain}`;
}

function renderAuditSummary(report) {
  if (!report) { setText('audit-headline', 'No audit run yet.'); return; }
  const verified = report.total - report.unverified;
  setText('audit-headline', `${report.breached_percent}% of ${verified} test accounts use a breached password`);
  setText('audit-total', report.total); setText('audit-breached', report.breached);
  setText('audit-short', report.below_policy); setText('audit-unverified', report.unverified);
}

async function runAccountAudit(text, sourceName) {
  const accounts = parseAccountCsv(text).slice(0, 5000);
  if (!accounts.length) { toast('No accounts found. Expected a CSV with an email,password header.'); return; }
  setText('audit-headline', `Hashing ${accounts.length} passwords locally…`);
  const rows = [];
  for (const account of accounts) {
    const normalized = normalizePassword(account.password);
    const digest = (await sha1Hex(normalized)).toUpperCase();
    rows.push({ email: account.email, length: [...normalized].length, prefix: digest.slice(0, 5), suffix: digest.slice(5) });
    account.password = ''; // drop plaintext reference as soon as it is hashed
  }
  const prefixes = [...new Set(rows.map((r) => r.prefix))];
  const ranges = new Map();
  let done = 0; let liveCount = 0; let offlineCount = 0;
  const queue = [...prefixes];
  const worker = async () => {
    while (queue.length) {
      const prefix = queue.shift();
      try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { headers: { 'Add-Padding': 'true' } });
        if (!response.ok) throw new Error(`HIBP HTTP ${response.status}`);
        const map = new Map();
        for (const line of (await response.text()).split(/\r?\n/)) {
          const [suf, cnt] = line.trim().split(':');
          if (suf && Number(cnt) > 0) map.set(suf.toUpperCase(), Number(cnt)); // padded entries have count 0
        }
        ranges.set(prefix, { mode: 'live', map }); liveCount++;
      } catch {
        const fixture = OFFLINE_DEMO[prefix];
        ranges.set(prefix, fixture ? { mode: 'offline-demo', map: new Map(Object.entries(fixture).map(([k, v]) => [k, v || -1])) } : { mode: 'unavailable', map: null });
        if (fixture) offlineCount++;
      }
      done++;
      $('#audit-progress')?.style.setProperty('width', `${Math.round(done / prefixes.length * 100)}%`);
      setText('audit-requests', `${done}/${prefixes.length}`);
    }
  };
  await Promise.all(Array.from({ length: Math.min(6, prefixes.length) }, worker));
  let breached = 0; let unverified = 0; let short = 0;
  const html = rows.map((row) => {
    const range = ranges.get(row.prefix);
    const belowPolicy = row.length < 15;
    if (belowPolicy) short++;
    let result; let count = '—'; let cls;
    if (range.map && range.map.has(row.suffix)) {
      breached++; const c = range.map.get(row.suffix);
      result = 'BREACHED'; cls = 'bad'; count = c > 0 ? c.toLocaleString() : 'demo fixture';
    } else if (range.mode === 'live') {
      result = 'CLEAN'; cls = 'good';
    } else {
      // Only a live range can prove a password is absent from the breach corpus.
      unverified++; result = 'UNVERIFIED'; cls = 'warn';
    }
    return `<tr><td>${escapeHtml(maskEmail(row.email))}</td><td><span class="status-chip ${cls}">${result}</span></td><td>${count}</td><td>${belowPolicy ? 'Below 15 chars' : 'OK'}</td></tr>`;
  }).join('');
  $('#audit-rows').innerHTML = html;
  const mode = liveCount && offlineCount ? 'mixed' : liveCount ? 'live' : offlineCount ? 'offline-demo' : 'unavailable';
  const payload = { source_name: sourceName, total: rows.length, breached, unverified, below_policy: short, hibp_mode: mode };
  try {
    const saved = await api('/api/audit/accounts', { method: 'POST', body: JSON.stringify(payload) });
    renderAuditSummary(saved);
  } catch (error) {
    renderAuditSummary({ ...payload, breached_percent: rows.length - unverified ? Math.round(breached / (rows.length - unverified) * 1000) / 10 : 0 });
    toast(`Audit computed locally but not saved: ${error.message}`);
  }
  if (mode !== 'live') toast(mode === 'offline-demo' ? 'HIBP unreachable: breached matches come from the offline demo fixture; other accounts are UNVERIFIED.' : 'Audit complete (some prefixes were unverified).');
  else toast(`Audit complete: ${breached} of ${rows.length} test accounts use a breached password.`);
}

$('#audit-browse')?.addEventListener('click', () => $('#audit-file')?.click());
$('#audit-file')?.addEventListener('change', async (event) => {
  const file = event.target.files?.[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) { toast('CSV too large for the demo audit (2 MB max).'); return; }
  await runAccountAudit(await file.text(), file.name);
  event.target.value = '';
});
$('#audit-sample')?.addEventListener('click', async () => {
  try {
    const response = await fetch('/api/demo/sample-accounts.csv', { credentials: 'same-origin' });
    if (!response.ok) throw new Error('Sample list unavailable');
    await runAccountAudit(await response.text(), 'sample-accounts.csv');
  } catch (error) { toast(error.message); }
});

$('#export-report')?.addEventListener('click', () => { window.location.href = '/api/admin/report.csv'; });
$('#judge-tour')?.addEventListener('click', () => { nav('password'); toast('Judge tour: predictable password → HIBP → SecretGuard → Exposure Graph → remediation.'); });

// ---------------- Authentication UI ----------------
// Three separate forms (sign in / create account / reset). After sign-in the topbar shows an
// account menu with role and Sign out; the auth modal can no longer be opened while signed in.
const authModal = $('#login-modal');
let resetToken = null;
let demoAccounts = null;

function openAuth(tab = 'signin') {
  if (state.auth) { toggleAccountMenu(true); return; }
  setAuthTab(tab);
  authModal?.classList.add('open');
  setTimeout(() => authModal?.querySelector('.auth-form:not(.hidden) input')?.focus(), 60);
}
function closeAuth() {
  authModal?.classList.remove('open');
  $$('#login-modal input').forEach((input) => { if (input.type === 'password' || input.dataset.revealed) { input.value = ''; input.type = 'password'; } });
}
function setAuthTab(tab) {
  const titles = { signin: ['Welcome back', 'Your password never leaves this browser. We verify a proof derived from it.'],
    signup: ['Create your account', 'Checked against known breaches before it is accepted. Only a 5-character hash prefix leaves this browser.'],
    reset: ['Reset your password', 'The new password goes through the same breach gate as signup.'] };
  $$('.auth-tab').forEach((b) => { const on = b.dataset.authTab === tab; b.classList.toggle('active', on); b.setAttribute('aria-selected', on); });
  $$('#login-modal .auth-form').forEach((f) => f.classList.toggle('hidden', f.dataset.authForm !== tab));
  $('#auth-title').textContent = titles[tab][0];
  $('#auth-subtitle').textContent = titles[tab][1];
  if (tab === 'reset' && !resetToken) { $('#reset-step-1').classList.remove('hidden'); $('#reset-step-2').classList.add('hidden'); $('#reset-submit').textContent = 'Send reset link'; }
  const carry = ['signin-email', 'signup-email', 'reset-email'].map((id) => $('#' + id)?.value).find(Boolean) || '';
  ['signin-email', 'signup-email', 'reset-email'].forEach((id) => { if ($('#' + id) && !$('#' + id).value) $('#' + id).value = carry; });
  $$('#login-modal .auth-status').forEach((s) => { s.className = 'auth-status'; s.textContent = ''; });
}
function authSay(form, cls, text) { const el = $(`#${form}-status`); if (el) { el.className = `auth-status show ${cls}`; el.textContent = text; } }
function setBusy(button, busy, label) { if (!button) return; if (busy) { button.dataset.label = button.textContent; button.textContent = label; } else if (button.dataset.label) button.textContent = button.dataset.label; button.disabled = busy; }

$('#login-open')?.addEventListener('click', () => openAuth('signin'));
$('#login-close')?.addEventListener('click', closeAuth);
authModal?.addEventListener('click', (e) => { if (e.target === authModal) closeAuth(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { closeAuth(); toggleAccountMenu(false); } });
$$('[data-auth-tab]').forEach((b) => b.addEventListener('click', () => setAuthTab(b.dataset.authTab)));
$$('[data-reveal]').forEach((b) => b.addEventListener('click', () => {
  const input = $('#' + b.dataset.reveal); if (!input) return;
  input.type = input.type === 'password' ? 'text' : 'password';
  b.setAttribute('aria-label', input.type === 'password' ? 'Show password' : 'Hide password');
}));

// Live policy checklist (local only; the breach check runs on submit).
function updatePolicyList(kind) {
  const pw = normalizePassword($(kind === 'sec' ? '#sec-new' : `#${kind}-password`)?.value || '');
  const confirm = normalizePassword($(`#${kind}-confirm`)?.value || '');
  const email = (kind === 'signup' ? $('#signup-email')?.value : kind === 'sec' ? state.auth?.email : $('#reset-email')?.value) || '';
  const local = email.split('@')[0].toLowerCase();
  const lower = pw.toLowerCase();
  const rules = {
    length: [...pw].length >= 15,
    common: pw.length > 0 && !COMMON.has(lower),
    context: pw.length > 0 && !(local.length >= 4 && lower.includes(local)) && !lower.includes('privpass'),
    match: pw.length > 0 && pw === confirm,
  };
  $$(`[data-policy-for="${kind}"] li`).forEach((li) => {
    const rule = li.dataset.rule; if (!(rule in rules)) return;
    li.classList.toggle('ok', rules[rule]); li.classList.toggle('bad', pw.length > 0 && !rules[rule]);
  });
  const analysis = pw ? analyzePasswordModel(pw, false) : { score: 0 };
  const meter = $(`#${kind}-meter`);
  if (meter) { meter.style.width = `${analysis.score}%`; meter.dataset.level = analysis.score >= 80 ? 'high' : analysis.score >= 55 ? 'mid' : 'low'; }
  return Object.values(rules).every(Boolean);
}
['signup', 'reset'].forEach((kind) => ['password', 'confirm'].forEach((f) => $(`#${kind}-${f}`)?.addEventListener('input', () => updatePolicyList(kind))));

// ---- Password managers (Chrome / Google Password Manager "Use suggested password", 1Password, Bitwarden…)
// Managers fill fields in ways that don't always look like typing: a plain (non-keyboard) input event, a change
// event only, a paste, or setting the value with no event at all. Every password field is watched for all of
// them, and when a manager fills a NEW password while "Confirm" is still empty, the confirmation is filled too
// (the manager has stored the exact value, so retyping it would only add friction).
const managedFields = [];
function watchPasswordField(input, onChange) {
  if (!input) return;
  const entry = { input, last: input.value, onChange };
  input._ppWatch = entry;
  managedFields.push(entry);
  const handle = (managed) => { if (input.value === entry.last) return; entry.last = input.value; onChange(managed); };
  input.addEventListener('input', (e) => handle(!e.inputType || e.inputType === 'insertReplacementText' || e.inputType === 'insertFromPaste'));
  ['change', 'blur', 'keyup'].forEach((t) => input.addEventListener(t, () => handle(true)));
  input.addEventListener('animationstart', (e) => { if (e.animationName === 'pp-autofill') handle(true); });
}
setInterval(() => managedFields.forEach((f) => { if (f.input.value !== f.last) { f.last = f.input.value; f.onChange(true); } }), 400);

function linkConfirm(pwSel, confirmSel, kind, noteId) {
  const pw = $(pwSel); const confirm = $(confirmSel);
  watchPasswordField(pw, (managed) => {
    const v = pw.value;
    if (managed && v && (!confirm.value || confirm.dataset.autofilled === '1')) {
      confirm.value = v; confirm.dataset.autofilled = '1';
      if (confirm._ppWatch) confirm._ppWatch.last = v;   // our own write, not a user edit
      $('#' + noteId)?.classList.remove('hidden');
    } else if (!managed && confirm.dataset.autofilled === '1') {
      confirm.value = ''; confirm.dataset.autofilled = ''; $('#' + noteId)?.classList.add('hidden');
      if (confirm._ppWatch) confirm._ppWatch.last = '';
    }
    updatePolicyList(kind);
  });
  watchPasswordField(confirm, () => { confirm.dataset.autofilled = ''; $('#' + noteId)?.classList.add('hidden'); updatePolicyList(kind); });
}
linkConfirm('#signup-password', '#signup-confirm', 'signup', 'signup-pm-note');
linkConfirm('#reset-password', '#reset-confirm', 'reset', 'reset-pm-note');
linkConfirm('#sec-new', '#sec-confirm', 'sec', 'sec-pm-note');
watchPasswordField($('#pw-input'), () => { clearTimeout(state.analyzeTimer); resetBreachEvidence(); state.analyzeTimer = setTimeout(refreshPasswordAnalysis, 60); });
$('#signup-email')?.addEventListener('input', () => updatePolicyList('signup'));

// Reject-on-breach gate shared by signup and reset. The server issues a single-use ticket; the
// browser spends it either on the account write (clean live check) or on /breach-gate/reject, so
// every attempt - accepted or blocked - is counted without any password data leaving the browser.
async function runBreachGate(purpose, password, email = '') {
  const form = purpose === 'reset' ? 'reset' : purpose === 'change' ? 'sec' : 'signup';
  const label = purpose === 'reset' ? 'Reset' : purpose === 'change' ? 'Password change' : 'Signup';
  const say = (cls, text) => authSay(form, cls, text);
  const breachLi = $(`[data-policy-for="${form}"] [data-rule="breach"]`);
  const { ticket, policy } = await api('/api/auth/breach-ticket', { method: 'POST', body: JSON.stringify({ purpose }) });
  const normalized = normalizePassword(password);
  const analysis = analyzePasswordModel(normalized, false);
  const reject = async (reason, message) => {
    say('bad', message);
    if (reason === 'breached' && breachLi) { breachLi.classList.remove('pending', 'ok'); breachLi.classList.add('bad'); }
    try { await api('/api/auth/breach-gate/reject', { method: 'POST', body: JSON.stringify({ ticket, reason }) }); } catch {}
    return { ok: false };
  };
  if (COMMON.has(normalized.toLowerCase())) return reject('breached', `${label} blocked: this is one of the most commonly guessed passwords.`);
  if ([...normalized].length < policy.min_length) return reject('below_policy', `${label} blocked: password-only accounts need ${policy.min_length}+ characters (NIST SP 800-63B).`);
  if ([...normalized].length > policy.max_length) return reject('below_policy', `${label} blocked: maximum length is ${policy.max_length} characters.`);
  // NIST 800-63B: also block context-specific words such as the username / service name.
  const localPart = String(email).split('@')[0].toLowerCase();
  const lowered = normalized.toLowerCase();
  if ((localPart.length >= 4 && lowered.includes(localPart)) || lowered.includes('privpass')) return reject('below_policy', `${label} blocked: the password contains your username or the service name.`);
  // 1) Local corpus first: a Bloom filter of 1M leaked passwords checked entirely in this browser.
  const local = window.PrivPassBloom ? await window.PrivPassBloom.check(normalized).catch(() => null) : null;
  if (local === true) return reject('breached', `${label} blocked: this password is in the top 1 million leaked passwords (checked offline — nothing left this browser).`);
  // 2) Live HIBP range check (k-anonymity: only a 5-character SHA-1 prefix leaves the browser).
  say('info', 'Checking known breaches — only a 5-character SHA-1 prefix leaves this browser…');
  const hibp = await lookupHibp(normalized);
  if (hibp.status === 'breached') return reject('breached', `${label} blocked: this password appears in known breach data${hibp.count ? ` (${hibp.count.toLocaleString()} times)` : ''}. Choose a different one.`);
  let mode = 'live';
  if (hibp.status !== 'safe' || hibp.mode !== 'live') {
    if (local === false && (policy.accepted_modes || []).includes('local-corpus')) mode = 'local-corpus';
    else return reject('unavailable', `${label} blocked: breach verification is unavailable, so the password cannot be accepted (fail-closed). Try again shortly.`);
  }
  if (breachLi) { breachLi.classList.remove('pending', 'bad'); breachLi.classList.add('ok'); }
  say('good', mode === 'live' ? 'Breach gate passed: not in the local corpus and no match in the live HIBP range.' : 'HIBP unreachable — accepted by policy on the offline 1M-password corpus.');
  return { ok: true, analysis, evidence: { ticket, hibp_status: 'safe', hibp_mode: mode, password_length: [...normalized].length } };
}

async function signIn(email, password) {
  const challenge = await api('/api/auth/challenge', { method: 'POST', body: JSON.stringify({ email }) });
  const verifier = await loginSecret(password, challenge);
  const proof = await hmacHex(verifier, challenge.nonce);
  const body = { email, nonce: challenge.nonce, proof };
  if ((challenge.kdf || 1) < 2) {           // legacy account: upgrade to the bound credential while signing in
    const ws = bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
    body.upgrade = { watch_salt_b64: ws, ...(await watchMaterial(password, ws)) };
  }
  lockEmailHint = email;
  const data = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(body) });
  state.auth = data;
  await ensureCsrf();
  updateAuthUI();
  closeAuth();
  toast(`Signed in as ${data.email} (${data.role}).`);
  nav(data.role === 'admin' ? 'command' : 'overview');
  // The server re-checked this password against HIBP during sign-in (and keeps re-checking it on a schedule).
  return data;
}

$('#form-signin')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#signin-email').value.trim(); const password = $('#signin-password').value;
  if (!email || !password) { authSay('signin', 'bad', 'Enter your email and password.'); return; }
  const btn = $('#signin-submit'); setBusy(btn, true, 'Signing in…');
  try { authSay('signin', 'info', 'Deriving your proof locally…'); await signIn(email, password); }
  catch (error) { if (error.locked) { authSay('signin', 'bad', 'This password appeared in a data breach, so the account is locked. Reset your password to unlock it.'); return; }
    authSay('signin', 'bad', /invalid credentials/i.test(error.message) ? 'Email or password is incorrect.' : error.message); }
  finally { setBusy(btn, false); }
});

$('#form-signup')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#signup-email').value.trim(); const password = $('#signup-password').value;
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { authSay('signup', 'bad', 'Enter a valid email address.'); return; }
  if (password !== $('#signup-confirm').value) { authSay('signup', 'bad', 'The two passwords do not match.'); return; }
  const btn = $('#signup-submit'); setBusy(btn, true, 'Checking…');
  try {
    const gate = await runBreachGate('signup', password, email);
    if (!gate.ok) return;
    const cred = await newCredential(password);
    authSay('signup', 'info', 'The server is double-checking the breach database…');
    await api('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email, ...cred, score: gate.analysis.score, score_label: gate.analysis.label, breached: false, breach_gate: gate.evidence }) });
    authSay('signup', 'good', 'Account created — signing you in…');
    await signIn(email, password);
  } catch (error) { authSay('signup', 'bad', error.message); }
  finally { setBusy(btn, false); }
});

$('#form-reset')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = $('#reset-email').value.trim();
  const btn = $('#reset-submit');
  try {
    if (!resetToken) {
      if (!email) { authSay('reset', 'bad', 'Enter the email for your account.'); return; }
      setBusy(btn, true, 'Sending…');
      const data = await api('/api/auth/reset/request', { method: 'POST', body: JSON.stringify({ email }) });
      if (!data.demo_token) { authSay('reset', 'info', 'If an account exists for that email, a reset link has been sent.'); return; }
      resetToken = data.demo_token;
      $('#reset-for').textContent = email;
      $('#reset-step-1').classList.add('hidden'); $('#reset-step-2').classList.remove('hidden');
      setBusy(btn, false); btn.textContent = 'Set new password';
      authSay('reset', 'info', 'Demo mode: reset link verified. Choose a new password.');
      $('#reset-password').focus();
      return;
    }
    const password = $('#reset-password').value;
    if (password !== $('#reset-confirm').value) { authSay('reset', 'bad', 'The two passwords do not match.'); return; }
    setBusy(btn, true, 'Checking…');
    const gate = await runBreachGate('reset', password, email);
    if (!gate.ok) return;
    const cred = await newCredential(password);
    await api('/api/auth/reset/complete', { method: 'POST', body: JSON.stringify({ token: resetToken, ...cred, score: gate.analysis.score, score_label: gate.analysis.label, breached: false, breach_gate: gate.evidence }) });
    resetToken = null;
    $('#reset-password').value = ''; $('#reset-confirm').value = '';
    setAuthTab('signin'); $('#signin-email').value = email;
    authSay('signin', 'good', 'Password updated and all other sessions signed out. Sign in with your new password.');
  } catch (error) { authSay('reset', 'bad', error.message); }
  finally { setBusy(btn, false); }
});

// Demo quick-fill (development mode only).
$$('[data-demo-role]').forEach((b) => b.addEventListener('click', () => {
  const acct = demoAccounts?.[b.dataset.demoRole]; if (!acct) return;
  $('#signin-email').value = acct.email; $('#signin-password').value = acct.password;
  authSay('signin', 'info', `Demo ${b.dataset.demoRole} filled in — press Sign in.`);
}));

// Signed-in account menu.
const ROLE_RANK = { user: 1, analyst: 2, admin: 3 };
function toggleAccountMenu(force) {
  const menu = $('#account-menu'); if (!menu) return;
  const open = force ?? !menu.classList.contains('open');
  menu.classList.toggle('open', open && !!state.auth);
  $('#account-chip')?.setAttribute('aria-expanded', String(open && !!state.auth));
}
function updateAuthUI() {
  const me = state.auth;
  document.body.dataset.auth = me ? 'in' : 'out';
  document.body.dataset.role = me?.role || '';
  document.body.dataset.workspace = me?.workspace || '';
  $('#ws-pill')?.classList.toggle('hidden', me?.workspace !== 'demo');
  $('#login-open')?.classList.toggle('hidden', !!me);
  $('#account-menu')?.classList.toggle('hidden', !me);
  if (me) {
    const initial = (me.email || '?').trim()[0].toUpperCase();
    ['#account-avatar', '#account-avatar-lg'].forEach((s) => setText(s.slice(1), initial));
    setText('account-email', me.email); setText('account-email-lg', me.email);
    setText('account-role', me.role); setText('account-meta', `${me.role} · ${me.workspace === 'demo' ? 'demo workspace' : 'live workspace'} · MFA ${me.mfa_enabled ? 'on' : 'off'}`);
  } else toggleAccountMenu(false);
  $$('[data-role-min]').forEach((el) => { el.classList.toggle('hidden', !me || (ROLE_RANK[me.role] || 0) < (ROLE_RANK[el.dataset.roleMin] || 9)); });
}
$('#account-chip')?.addEventListener('click', (e) => { e.stopPropagation(); $('#bell')?.classList.remove('open'); toggleAccountMenu(); });
// Every dropdown closes with its ✕ button, Esc, a second click on its trigger, or a click outside.
function closeDropdowns() { toggleAccountMenu(false); $('#bell')?.classList.remove('open'); $('#bell-btn')?.setAttribute('aria-expanded', 'false'); }
$$('[data-close-dropdown]').forEach((b) => b.addEventListener('click', (e) => { e.stopPropagation(); closeDropdowns(); }));
document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  const wasOpen = $('#account-menu')?.classList.contains('open') || $('#bell')?.classList.contains('open');
  closeDropdowns();
  if (wasOpen) (document.activeElement?.closest?.('#bell') ? $('#bell-btn') : $('#account-chip'))?.focus?.();
  $('#proof-drawer')?.classList.remove('open');
});
document.addEventListener('click', (e) => { if (!e.target.closest?.('#account-menu')) toggleAccountMenu(false); });
$$('[data-nav-account]').forEach((b) => b.addEventListener('click', () => { toggleAccountMenu(false); nav(b.dataset.navAccount); }));

async function signOut(reason = '') {
  try { if (state.auth) await api('/api/auth/logout', { method: 'POST', body: JSON.stringify({}) }); } catch {}
  state.auth = null;
  try { lockVault(true); } catch {}
  state.secretFindings = [];
  await ensureCsrf(true);
  updateAuthUI();
  nav('overview');
  toast(reason || 'Signed out. Your session has been revoked on the server.');
}
$('#sign-out')?.addEventListener('click', () => signOut());

$$('[data-transition]').forEach((button) => button.addEventListener('click', () => toast(`Demo lifecycle transition: ${button.dataset.transition}`)));

async function loadDemoInfo() {
  try {
    const data = await api('/api/demo/info');
    if (!data.demo_mode) return;
    $('#demo-admin-email').textContent = data.admin.email;
    $('#demo-admin-pass').textContent = data.admin.password;
    $('#demo-analyst-email').textContent = data.analyst.email;
    $('#demo-analyst-pass').textContent = data.analyst.password;
    if (data.user) { $('#demo-user-email').textContent = data.user.email; $('#demo-user-pass').textContent = data.user.password; }
    demoAccounts = { admin: data.admin, analyst: data.analyst, user: data.user };
    $('#demo-fill')?.classList.remove('hidden');
  } catch {}
}
$('#copy-admin')?.addEventListener('click', async () => {
  const text = `Email: ${$('#demo-admin-email').textContent}\nPassword: ${$('#demo-admin-pass').textContent}`;
  try { await navigator.clipboard.writeText(text); toast('Admin credentials copied.'); } catch { toast('Clipboard permission unavailable; use Demo Center text.'); }
});

ensureCsrf().then(hydrateAuth);
loadPublic();
loadDemoInfo();
$('#pw-input')?.focus({ preventScroll: true });

window.addEventListener('error', (event) => { if (event?.error) console.error(event.error); });

// Remove legacy Demo Center coaching blocks that older cached markup may still contain.
function removeLegacyDemoGuidance() {
  document.querySelectorAll('#view-demo .demo-notes, #view-demo .demo-ai-guidance, #view-demo .what-to-say, #view-demo .what-not-to-claim').forEach((el) => el.remove());
}
removeLegacyDemoGuidance();

// ---------------- Zero-knowledge Password Vault ----------------
function showVaultLocked(message = 'Sign in, then unlock using your master password.') {
  $('#vault-locked')?.classList.remove('hidden');
  $('#vault-unlocked')?.classList.add('hidden');
  if ($('#vault-status')) $('#vault-status').textContent = 'Vault locked';
  if ($('#vault-substatus')) $('#vault-substatus').textContent = message;
  $('#vault-status-dot')?.classList.add('locked');
  $('#vault-status-dot')?.classList.remove('unlocked');
  if ($('#vault-add')) $('#vault-add').disabled = true;
}

function showVaultUnlocked() {
  $('#vault-locked')?.classList.add('hidden');
  $('#vault-unlocked')?.classList.remove('hidden');
  if ($('#vault-status')) $('#vault-status').textContent = 'Vault unlocked';
  if ($('#vault-substatus')) $('#vault-substatus').textContent = 'Encrypted locally • admin cannot read vault entries';
  $('#vault-status-dot')?.classList.remove('locked');
  $('#vault-status-dot')?.classList.add('unlocked');
  if ($('#vault-add')) $('#vault-add').disabled = false;
}

async function deriveVaultKey(password, saltB64, iterations = 600000) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(normalizePassword(password)), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function encryptVaultPayload(record, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(record));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return JSON.stringify({ v: 1, iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ciphertext)) });
}

async function decryptVaultPayload(blob, key) {
  const parsed = JSON.parse(blob);
  if (!parsed || parsed.v !== 1) throw new Error('Unsupported vault record version');
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(parsed.iv) }, key, b64ToBytes(parsed.ct));
  return JSON.parse(new TextDecoder().decode(plain));
}

async function hydrateAuth() {
  try {
    const me = await api('/api/auth/me');
    state.auth = me;
    updateAuthUI();
    return me;
  } catch {
    state.auth = null;
    updateAuthUI();
    return null;
  }
}

async function unlockVault() {
  const master = $('#vault-master')?.value || '';
  if (!master) { toast('Enter your master password to unlock the vault.'); return; }
  try {
    const config = await api('/api/vault/config');
    const challenge = await api('/api/vault/challenge', { method: 'POST', body: JSON.stringify({}) });
    const verifier = await loginSecret(master, { salt_b64: config.auth_salt_b64, watch_salt_b64: config.auth_watch_salt_b64, kdf: config.auth_kdf });
    const proof = await hmacHex(verifier, challenge.nonce);
    const opened = await api('/api/vault/unlock', { method: 'POST', body: JSON.stringify({ proof, nonce: challenge.nonce }) });
    const key = await deriveVaultKey(master, opened.vault_salt_b64, opened.iterations);
    const checkMarker = 'PRIVPASS_VAULT_CHECK_V1';
    if (opened.vault_check_ciphertext) {
      const check = await decryptVaultPayload(opened.vault_check_ciphertext, key);
      if (check.marker !== checkMarker) throw new Error('Vault integrity check failed. The password does not match this vault.');
    } else {
      const checkBlob = await encryptVaultPayload({ marker: checkMarker, createdAt: new Date().toISOString() }, key);
      await api('/api/vault/check', { method: 'PUT', body: JSON.stringify({ ciphertext_b64: checkBlob }) });
    }
    state.vaultConfig = opened;
    state.vaultKey = key;
    await refreshVaultItems();
    $('#vault-master').value = '';
    showVaultUnlocked();
    resetVaultAutoLock();
    toast('Vault unlocked locally. The server never receives the master password.');
  } catch (error) {
    state.vaultKey = null;
    toast(`Vault unlock failed: ${error.message}`);
  }
}

async function refreshVaultItems() {
  if (!state.vaultKey) return;
  const payload = await api('/api/vault/items');
  const decoded = [];
  for (const item of payload) {
    try {
      const record = await decryptVaultPayload(item.ciphertext_b64, state.vaultKey);
      decoded.push({ ...record, id: item.id, createdAt: record.createdAt || item.created_at, updatedAt: record.updatedAt || item.updated_at });
    } catch {
      decoded.push({ id: item.id, corrupted: true, createdAt: item.created_at, updatedAt: item.updated_at });
    }
  }
  state.vaultItems = payload;
  state.vaultRecords = decoded;
  await renderVault();
}

async function renderVault() {
  const search = ($('#vault-search')?.value || '').trim().toLowerCase();
  const filter = $('#vault-filter')?.value || 'all';
  const now = Date.now();
  const passwordHashMap = new Map();
  for (const record of state.vaultRecords) {
    if (!record.password) continue;
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(record.password));
    const key = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
    passwordHashMap.set(key, (passwordHashMap.get(key) || 0) + 1);
  }
  let weak = 0, due = 0, reused = 0;
  const view = [];
  for (const record of state.vaultRecords) {
    if (record.corrupted) continue;
    const result = analyzePasswordModel(record.password || '', [record.username || '', record.site || ''], !!record.generated);
    const isDue = !!record.nextRotationAt && new Date(record.nextRotationAt).getTime() <= now;
    const hashDigest = record.password ? await crypto.subtle.digest('SHA-256', new TextEncoder().encode(record.password)) : null;
    const hashKey = hashDigest ? [...new Uint8Array(hashDigest)].map((b) => b.toString(16).padStart(2, '0')).join('') : '';
    const isReused = !!hashKey && (passwordHashMap.get(hashKey) || 0) > 1;
    if (result.score < 65 || result.verdict !== 'ACCEPT') weak += 1;
    if (isDue) due += 1;
    if (isReused) reused += 1;
    const hay = `${record.site || ''} ${record.username || ''} ${(record.tags || []).join(' ')}`.toLowerCase();
    if (search && !hay.includes(search)) continue;
    if (filter === 'weak' && !(result.score < 65 || result.verdict !== 'ACCEPT')) continue;
    if (filter === 'due' && !isDue) continue;
    if (filter === 'reused' && !isReused) continue;
    if (filter === 'favorite' && !record.favorite) continue;
    view.push({ record, result, isDue, isReused });
  }
  $('#vault-count').textContent = state.vaultRecords.filter((x) => !x.corrupted).length;
  $('#vault-weak').textContent = weak;
  $('#vault-due').textContent = due;
  $('#vault-reused').textContent = reused;
  $('#vault-posture').textContent = (weak === 0 && due === 0 && reused === 0) ? 'HEALTHY' : (weak + due + reused < 3 ? 'REVIEW' : 'ELEVATED');
  maybeVaultReminder(due);
  const health = $('#vault-health');
  if (health) health.innerHTML = `<div><b>Vault health</b><span>${escapeHtml(weak === 0 ? 'All saved passwords meet the local resilience target.' : `${weak} saved login(s) need stronger credentials.`)}</span></div><div><b>Privacy model</b><span>Server stores encrypted blobs only; titles and passwords remain client-side.</span></div><div><b>Rotation</b><span>${due ? `${due} reminder(s) are due.` : 'No reminders are due.'}</span></div>`;
  const list = $('#vault-list');
  if (!view.length) { list.innerHTML = '<div class="empty-state">No matching logins. Add a login or change the filter.</div>'; return; }
  list.innerHTML = view.map(({ record, result, isDue, isReused }) => {
    const masked = '•'.repeat(Math.min(20, Math.max(8, (record.password || '').length)));
    const status = result.score >= 85 ? 'strong' : result.score >= 65 ? 'review' : 'weak';
    const dueBadge = isDue ? '<span class="vault-badge danger">ROTATION DUE</span>' : '';
    const reusedBadge = isReused ? '<span class="vault-badge warn">REUSED</span>' : '';
    const breachBadge = record.breachStatus === 'breached' ? '<span class="vault-badge danger">BREACHED</span>' : record.breachStatus === 'safe' ? '<span class="vault-badge good">HIBP SAFE</span>' : '';
    return `<article class="vault-card" data-vault-id="${escapeHtml(record.id)}">
      <div class="vault-card-main"><div class="vault-site-mark">${escapeHtml((record.site || 'S').slice(0,1).toUpperCase())}</div><div><div class="vault-site-line"><h3>${escapeHtml(record.site || 'Untitled')}</h3>${record.favorite ? '<span class="favorite">★</span>' : ''}</div><p>${escapeHtml(record.username || 'No username')}</p>${record.tags?.length ? `<div class="tag-row">${record.tags.map((tag) => `<span>${escapeHtml(tag)}</span>`).join('')}</div>` : ''}</div></div>
      <div class="vault-badges">${dueBadge}${reusedBadge}${breachBadge}</div>
      <div class="vault-secret-line"><span class="vault-password-mask" data-revealed="false">${masked}</span><button class="icon-btn vault-reveal" data-id="${escapeHtml(record.id)}" aria-label="Reveal saved password">◉</button><button class="icon-btn vault-copy" data-id="${escapeHtml(record.id)}" aria-label="Copy saved password">⧉</button></div>
      <div class="vault-strength-line"><div><span>Local resilience</span><b>${result.score}/100 • ${escapeHtml(result.label)}</b></div><div class="vault-strength-bar"><i style="width:${result.score}%"></i></div></div>
      <div class="vault-actions-row"><button class="mini-action vault-copy-user" data-id="${escapeHtml(record.id)}">Copy user</button><button class="mini-action vault-open" data-id="${escapeHtml(record.id)}">Open site</button><button class="mini-action vault-rotate" data-id="${escapeHtml(record.id)}">Rotate</button><button class="mini-action vault-edit" data-id="${escapeHtml(record.id)}">Edit</button><button class="mini-action vault-hibp" data-id="${escapeHtml(record.id)}">Check breach</button><button class="mini-action vault-delete" data-id="${escapeHtml(record.id)}">Delete</button></div>
    </article>`;
  }).join('');
  $$('.vault-reveal').forEach((btn) => btn.addEventListener('click', () => revealVaultPassword(btn.dataset.id)));
  $$('.vault-copy').forEach((btn) => btn.addEventListener('click', () => copyVaultPassword(btn.dataset.id)));
  $$('.vault-copy-user').forEach((btn) => btn.addEventListener('click', () => copyVaultUsername(btn.dataset.id)));
  $$('.vault-open').forEach((btn) => btn.addEventListener('click', () => openVaultSite(btn.dataset.id)));
  $$('.vault-rotate').forEach((btn) => btn.addEventListener('click', () => rotateVaultItem(btn.dataset.id)));
  $$('.vault-edit').forEach((btn) => btn.addEventListener('click', () => openVaultEditor(btn.dataset.id)));
  $$('.vault-delete').forEach((btn) => btn.addEventListener('click', () => deleteVaultItem(btn.dataset.id)));
  $$('.vault-hibp').forEach((btn) => btn.addEventListener('click', () => checkVaultBreach(btn.dataset.id)));
}

async function maybeVaultReminder(dueCount) {
  if (!dueCount || !('Notification' in window)) return;
  const key = `privpass-vault-reminder-${new Date().toISOString().slice(0, 10)}`;
  if (safeStorage.get(key)) return;
  if (Notification.permission === 'granted') {
    new Notification('PrivPass Shield', { body: `${dueCount} vault review reminder(s) are due.` });
    safeStorage.set(key, '1');
  }
}

function resetVaultAutoLock() {
  clearTimeout(state.vaultAutoLockTimer);
  state.vaultAutoLockTimer = setTimeout(() => lockVault(true), 5 * 60 * 1000);
}
['pointerdown','keydown','touchstart'].forEach((eventName) => document.addEventListener(eventName, () => { if (state.vaultKey) resetVaultAutoLock(); }, { passive: true }));

function lockVault(silent = false) {
  state.vaultKey = null;
  state.vaultConfig = null;
  state.vaultRecords = [];
  state.vaultItems = [];
  clearTimeout(state.vaultAutoLockTimer);
  showVaultLocked('Locked. Your decrypted vault data was cleared from browser memory.');
  if (!silent) toast('Vault locked. Decrypted entries cleared from memory.');
}

async function loadVaultView() {
  const me = state.auth || await hydrateAuth();
  if (!me) { showVaultLocked('Sign in first. Admins can manage accounts, but cannot read vault contents.'); return; }
  if (state.vaultKey) { showVaultUnlocked(); await renderVault(); return; }
  showVaultLocked('Your vault is ready. Unlock it with the same master password used for your PrivPass account.');
}

function clearVaultEditor() {
  ['vault-site','vault-username','vault-password','vault-tags','vault-notes'].forEach((id) => { const el = $(`#${id}`); if (el) el.value = ''; });
  $('#vault-favorite').checked = false; $('#vault-remind').checked = true;
  $('#vault-editor').dataset.id = '';
  $('#vault-editor-title').textContent = 'Save a login';
  updateVaultEntryStrength();
}
function openVaultEditor(id = '') {
  if (!state.vaultKey) { toast('Unlock the vault first.'); return; }
  clearVaultEditor();
  const record = id ? state.vaultRecords.find((x) => x.id === id) : null;
  if (record) {
    $('#vault-editor').dataset.id = id; $('#vault-editor-title').textContent = 'Edit login';
    $('#vault-site').value = record.site || ''; $('#vault-username').value = record.username || ''; $('#vault-password').value = record.password || '';
    $('#vault-tags').value = (record.tags || []).join(', '); $('#vault-notes').value = record.notes || ''; $('#vault-favorite').checked = !!record.favorite;
    $('#vault-remind').checked = !!record.nextRotationAt;
  }
  $('#vault-editor').classList.add('open');
  updateVaultEntryStrength();
}

function updateVaultEntryStrength() {
  const value = $('#vault-password')?.value || '';
  const result = analyzePasswordModel(value, [$('#vault-username')?.value || '', $('#vault-site')?.value || ''], false);
  $('#vault-entry-strength-label').textContent = value ? result.label : 'Strength';
  $('#vault-entry-strength-score').textContent = value ? `${result.score}/100` : '—';
  $('#vault-entry-strength-reason').textContent = value ? (result.reasons[0] || 'No dominant low-effort pattern detected.') : 'Type a password to analyze it locally.';
  $('#vault-entry-strength-bar').style.width = `${result.score}%`;
}

async function saveVaultRecord() {
  if (!state.vaultKey) { toast('Unlock the vault first.'); return; }
  const site = $('#vault-site').value.trim(); const username = $('#vault-username').value.trim(); const password = $('#vault-password').value;
  if (!site || !username || !password) { toast('Website, username and password are required.'); return; }
  const existingId = $('#vault-editor').dataset.id || '';
  const existing = existingId ? state.vaultRecords.find((x) => x.id === existingId) : null;
  const now = new Date().toISOString();
  const record = {
    site, username, password,
    tags: $('#vault-tags').value.split(',').map((x) => x.trim()).filter(Boolean).slice(0, 12),
    notes: $('#vault-notes').value.trim(), favorite: $('#vault-favorite').checked,
    generated: !!(existing?.generated && existing.password === password),
    createdAt: existing?.createdAt || now, updatedAt: now,
    nextRotationAt: $('#vault-remind').checked ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString() : null,
    breachStatus: existing?.breachStatus || 'unknown', lastBreachCheck: existing?.lastBreachCheck || null,
  };
  try {
    const blob = await encryptVaultPayload(record, state.vaultKey);
    if (existingId) await api(`/api/vault/items/${encodeURIComponent(existingId)}`, { method: 'PUT', body: JSON.stringify({ ciphertext_b64: blob }) });
    else { const created = await api('/api/vault/items', { method: 'POST', body: JSON.stringify({ ciphertext_b64: blob }) }); record.id = created.id; }
    $('#vault-editor').classList.remove('open');
    await refreshVaultItems();
    toast(existingId ? 'Vault entry re-encrypted and saved.' : 'Login encrypted locally and saved to the vault.');
  } catch (error) { toast(`Vault save failed: ${error.message}`); }
}

async function deleteVaultItem(id) {
  const record = state.vaultRecords.find((x) => x.id === id);
  if (!record) return;
  if (!confirm(`Delete the saved login for ${record.site || 'this site'}?`)) return;
  try { await api(`/api/vault/items/${encodeURIComponent(id)}`, { method: 'DELETE' }); await refreshVaultItems(); toast('Encrypted vault record deleted.'); }
  catch (error) { toast(`Delete failed: ${error.message}`); }
}

function revealVaultPassword(id) {
  const record = state.vaultRecords.find((x) => x.id === id); const card = document.querySelector(`.vault-card[data-vault-id="${CSS.escape(id)}"]`); if (!record || !card) return;
  const el = card.querySelector('.vault-password-mask'); const revealed = el.dataset.revealed === 'true'; el.dataset.revealed = revealed ? 'false' : 'true'; el.textContent = revealed ? '•'.repeat(Math.min(20, Math.max(8, record.password.length))) : record.password; resetVaultAutoLock();
}
async function copyVaultPassword(id) {
  const record = state.vaultRecords.find((x) => x.id === id); if (!record) return;
  try { await navigator.clipboard.writeText(record.password); toast('Password copied. It is never written to the database.'); resetVaultAutoLock(); }
  catch { toast('Clipboard access is unavailable. Use the eye control to reveal it locally.'); }
}

async function copyVaultUsername(id) {
  const record = state.vaultRecords.find((x) => x.id === id); if (!record) return;
  try { await navigator.clipboard.writeText(record.username || ''); toast('Username copied locally.'); resetVaultAutoLock(); }
  catch { toast('Clipboard access is unavailable.'); }
}
function openVaultSite(id) {
  const record = state.vaultRecords.find((x) => x.id === id); if (!record) return;
  let url = String(record.site || '').trim(); if (!url) { toast('No site URL saved.'); return; }
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  window.open(url, '_blank', 'noopener,noreferrer');
  resetVaultAutoLock();
}
function rotateVaultItem(id) {
  const record = state.vaultRecords.find((x) => x.id === id); if (!record) return;
  openVaultEditor(id);
  const mode = $('#vault-gen-mode'); const length = $('#vault-gen-length');
  if (mode) mode.value = 'random'; if (length) length.value = String(Math.max(32, Math.min(48, Number(length?.value || 32))));
  $('#vault-password').value = generateSecureSecret(Number(length?.value || 32));
  $('#vault-remind').checked = true;
  $('#vault-editor-title').textContent = 'Rotate login secret';
  updateVaultEntryStrength();
  toast('New secret generated locally. Save it after updating the service.');
}

async function checkVaultBreach(id) {
  const record = state.vaultRecords.find((x) => x.id === id); if (!record) return;
  toast('Checking this saved password with HIBP. Only the 5-character SHA-1 prefix leaves the browser.');
  try {
    const result = await lookupHibp(record.password);
    record.breachStatus = result.status; record.lastBreachCheck = new Date().toISOString();
    const blob = await encryptVaultPayload(record, state.vaultKey);
    await api(`/api/vault/items/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify({ ciphertext_b64: blob }) });
    await refreshVaultItems();
    toast(result.status === 'breached' ? `BREACHED: ${record.site} should be changed immediately.` : result.status === 'safe' ? `HIBP SAFE: no match for ${record.site}.` : 'HIBP verification unavailable.');
  } catch (error) { toast(`Breach check failed: ${error.message}`); }
}

async function seedDemoVault() {
  if (!state.vaultKey) { toast('Unlock the vault first.'); return; }
  const samples = [
    { site:'instagram.com', username:'op_09', password:generateSecureSecret(28), tags:['social'], notes:'Demo only — generated locally.', favorite:true },
    { site:'github.com', username:'demo-dev', password:generateSecurePassphrase(6), tags:['work','code'], notes:'Demo only — generated locally.', favorite:false },
    { site:'bank.example', username:'secure-user', password:generateSecureSecret(36), tags:['finance'], notes:'Demo-only synthetic entry.', favorite:true },
  ];
  for (const sample of samples) {
    const record = { ...sample, generated:true, createdAt:new Date().toISOString(), updatedAt:new Date().toISOString(), nextRotationAt:new Date(Date.now()+30*24*60*60*1000).toISOString(), breachStatus:'unknown', lastBreachCheck:null };
    const blob = await encryptVaultPayload(record, state.vaultKey);
    await api('/api/vault/items', { method:'POST', body:JSON.stringify({ ciphertext_b64:blob}) });
  }
  await refreshVaultItems(); toast('Three synthetic demo logins were encrypted locally and added.');
}

async function importEncryptedVault(file) {
  if (!state.vaultKey) { toast('Unlock the vault first.'); return; }
  try {
    const payload = JSON.parse(await file.text());
    if (payload.version !== 1 || !Array.isArray(payload.items)) throw new Error('Unsupported backup format.');
    if (payload.vaultSaltB64 && payload.vaultSaltB64 !== state.vaultConfig?.vault_salt_b64) throw new Error('This backup belongs to a different vault. Use the matching account/master password.');
    let imported = 0;
    for (const item of payload.items) {
      if (!item?.ciphertext_b64) continue;
      await decryptVaultPayload(item.ciphertext_b64, state.vaultKey);
      await api('/api/vault/items', { method: 'POST', body: JSON.stringify({ ciphertext_b64: item.ciphertext_b64 }) });
      imported += 1;
    }
    await refreshVaultItems();
    toast(`Imported ${imported} encrypted vault item(s).`);
  } catch (error) { toast(`Encrypted backup import failed: ${error.message}`); }
}

function exportEncryptedVault() {
  if (!state.vaultKey) { toast('Unlock the vault first.'); return; }
  const payload = { version:1, exportedAt:new Date().toISOString(), note:'PrivPass encrypted vault backup. Contents are ciphertext only.', vaultSaltB64:state.vaultConfig?.vault_salt_b64 || null, items:state.vaultItems };
  const blob = new Blob([JSON.stringify(payload,null,2)], { type:'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url; a.download=`privpass-encrypted-vault-${new Date().toISOString().slice(0,10)}.json`; a.click(); URL.revokeObjectURL(url); toast('Encrypted vault backup exported. It contains ciphertext, not plaintext passwords.');
}

$('#vault-unlock')?.addEventListener('click', unlockVault);
$('#vault-master')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') unlockVault(); });
$('#vault-lock')?.addEventListener('click', () => lockVault(false));
$('#vault-add')?.addEventListener('click', () => openVaultEditor());
$('#vault-editor-close')?.addEventListener('click', () => $('#vault-editor').classList.remove('open'));
$('#vault-editor-cancel')?.addEventListener('click', () => $('#vault-editor').classList.remove('open'));
$('#vault-save')?.addEventListener('click', saveVaultRecord);
$('#vault-password')?.addEventListener('input', updateVaultEntryStrength);
$('#vault-username')?.addEventListener('input', updateVaultEntryStrength);
$('#vault-site')?.addEventListener('input', updateVaultEntryStrength);
$('#vault-password-reveal')?.addEventListener('click', () => { const el=$('#vault-password'); el.type = el.type === 'password' ? 'text' : 'password'; });
$('#vault-gen-length')?.addEventListener('input', () => { $('#vault-gen-length-value').textContent = `${$('#vault-gen-mode').value === 'passphrase' ? Math.max(4, Math.min(8, Math.round(Number($('#vault-gen-length').value)/8))) + ' words' : $('#vault-gen-length').value + ' chars'}`; });
$('#vault-gen-mode')?.addEventListener('change', () => { $('#vault-gen-length').value = $('#vault-gen-mode').value === 'passphrase' ? 48 : 32; $('#vault-gen-length-value').textContent = $('#vault-gen-mode').value === 'passphrase' ? '6 words' : '32 chars'; });
$('#vault-generate')?.addEventListener('click', () => { const mode=$('#vault-gen-mode').value; const len=Number($('#vault-gen-length').value||32); $('#vault-password').value = mode==='passphrase' ? generateSecurePassphrase(Math.max(4,Math.min(8,Math.round(len/8)))) : generateSecureSecret(len); updateVaultEntryStrength(); toast('Generated locally with Web Crypto.'); });
$('#vault-search')?.addEventListener('input', () => { if (state.vaultKey) renderVault(); });
$('#vault-filter')?.addEventListener('change', () => { if (state.vaultKey) renderVault(); });
$('#vault-demo-seed')?.addEventListener('click', seedDemoVault);
$('#vault-export')?.addEventListener('click', exportEncryptedVault);
$('#vault-import-btn')?.addEventListener('click', () => $('#vault-import-file')?.click());
$('#vault-import-file')?.addEventListener('change', (e) => { const file = e.target.files?.[0]; if (file) importEncryptedVault(file); e.target.value = ''; });
$('#vault-reminder-enable')?.addEventListener('click', async () => { if (!('Notification' in window)) { toast('This browser does not support desktop notifications.'); return; } const result = await Notification.requestPermission(); toast(result === 'granted' ? 'Vault review reminders are enabled on this browser.' : 'Reminder permission was not granted; due dates remain visible in the vault.'); });

// Keep the vault toolbar inactive until an authenticated unlock succeeds.
showVaultLocked();

// ---------------- AI Lab ----------------
// Minimal, safe Markdown renderer: escape first, then add a small set of formatting rules.
function renderMarkdown(md) {
  const lines = escapeHtml(md || '').split('\n');
  const out = []; let list = null; let table = [];
  const inline = (t) => t.replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>').replace(/(^|\W)_([^_]+)_(?=\W|$)/g, '$1<em>$2</em>');
  const flushList = () => { if (list) { out.push(`</${list}>`); list = null; } };
  const flushTable = () => {
    if (!table.length) return;
    const rows = table.filter((r) => !/^\|\s*-/.test(r)).map((r) => r.replace(/^\||\|$/g, '').split('|').map((c) => inline(c.trim())));
    out.push(`<div class="md-table"><table><thead><tr>${rows[0].map((c) => `<th>${c}</th>`).join('')}</tr></thead><tbody>${rows.slice(1).map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
    table = [];
  };
  for (const raw of lines) {
    const line = raw.trimEnd();
    if (/^\|.*\|$/.test(line.trim())) { flushList(); table.push(line.trim()); continue; }
    flushTable();
    let m;
    if ((m = line.match(/^(#{1,3})\s+(.*)$/))) { flushList(); out.push(`<h${m[1].length + 2}>${inline(m[2])}</h${m[1].length + 2}>`); }
    else if ((m = line.match(/^\s*[-*]\s+\[( |x)\]\s+(.*)$/))) { if (list !== 'ul') { flushList(); out.push('<ul class="checklist">'); list = 'ul'; } out.push(`<li class="${m[1] === 'x' ? 'done' : ''}">${inline(m[2])}</li>`); }
    else if ((m = line.match(/^\s*[-*]\s+(.*)$/))) { if (list !== 'ul') { flushList(); out.push('<ul>'); list = 'ul'; } out.push(`<li>${inline(m[1])}</li>`); }
    else if ((m = line.match(/^\s*\d+\.\s+(.*)$/))) { if (list !== 'ol') { flushList(); out.push('<ol>'); list = 'ol'; } out.push(`<li>${inline(m[1])}</li>`); }
    else if (!line.trim()) { flushList(); }
    else { flushList(); out.push(`<p>${inline(line)}</p>`); }
  }
  flushList(); flushTable();
  return out.join('');
}

function compareBars(rows) {
  // rows: [label, value 0..1, variant, display]
  return rows.map(([label, value, variant, display]) => `<div class="cmp-row ${variant || ''}"><span>${escapeHtml(label)}</span><div class="cmp-track"><i style="width:${Math.max(1.5, Math.min(100, value * 100))}%"></i></div><b>${escapeHtml(display ?? `${Math.round(value * 100)}%`)}</b></div>`).join('');
}

async function loadModelCards() {
  try {
    const cards = await api('/api/ai/models');
    const sc = cards.secret_classifier;
    if (sc) {
      $('#mc-secret').innerHTML = `<div class="cmp-title">Secrets caught (recall, held-out files)</div>` + compareBars([
        ['ML model', sc.test.ml.recall, 'ai'], ['Rules only', sc.test.rules_baseline.recall, 'base']]) +
        `<div class="cmp-title">Precision</div>` + compareBars([['ML model', sc.test.ml.precision, 'ai'], ['Rules only', sc.test.rules_baseline.precision, 'base']]) +
        `<div class="cmp-title">False alarms on tricky look-alikes (hashes, placeholders, public keys)</div>` + compareBars([
          ['ML model', sc.by_source.synthetic_neg?.ml_flag_rate || 0, 'ai', `${((sc.by_source.synthetic_neg?.ml_flag_rate || 0) * 100).toFixed(2)}%`],
          ['Rules only', sc.by_source.synthetic_neg?.rules_flag_rate || 0, 'base', `${((sc.by_source.synthetic_neg?.rules_flag_rate || 0) * 100).toFixed(2)}%`]]);
      setText('mc-secret-foot', `${sc.data.real_oss_literals.toLocaleString()} real open-source literals from ${sc.data.files.toLocaleString()} files + ${sc.data.synthetic_positives.toLocaleString()} synthetic credentials · grouped split by file · threshold ${sc.threshold} · ${sc.trees} trees`);
    }
    const pm = cards.password_model;
    if (pm) {
      const ev = pm.evaluation;
      $('#mc-password').innerHTML = `<div class="cmp-title">Held-out leaked passwords recognised as guessable (≤ 10¹² guesses)</div>` + compareBars([
        ['Neural (ours)', ev.neural.held_out_leaked_guessed_within['<=1e12'], 'ai'], ['Rules v5', ev.heuristic_v5.held_out_leaked_guessed_within['<=1e12'], 'base'],
        ...(ev.zxcvbn ? [['zxcvbn*', ev.zxcvbn.held_out_leaked_guessed_within['<=1e12'], 'ref']] : [])]) +
        `<div class="cmp-title">Truly random 12–20 char passwords wrongly rated weak (lower is better)</div>` + compareBars([
          ['Neural (ours)', ev.neural.random_12_20_char_rated_weak_within_1e12, 'ai'], ['Rules v5', ev.heuristic_v5.random_12_20_char_rated_weak_within_1e12, 'base'],
          ...(ev.zxcvbn ? [['zxcvbn*', ev.zxcvbn.random_12_20_char_rated_weak_within_1e12, 'ref']] : [])]);
      setText('mc-password-foot', `${pm.params.toLocaleString()} parameters · ${pm.train_draws.toLocaleString()} training draws · ${pm.held_out.toLocaleString()} held-out passwords · int8 error ${pm.quantisation_mean_abs_error_bits} bits · *zxcvbn ships this same leaked list in its dictionary, so its leaked-password score is optimistic.`);
    }
    const an = cards.anomaly_detector;
    if (an) {
      const e = an.evaluation;
      $('#mc-anomaly').innerHTML = `<div class="cmp-title">Attack windows detected</div>` + compareBars([
        ['Credential stuffing', e.detect_credential_stuffing, 'ai'], ['Brute force', e.detect_brute_force, 'ai'], ['Enumeration', e.detect_enumeration, 'ai']]) +
        `<div class="cmp-title">False alarms on normal traffic</div>` + compareBars([['Normal windows flagged', e.false_alarm_rate, 'base', `${(e.false_alarm_rate * 100).toFixed(1)}%`]]);
      setText('mc-anomaly-foot', `${an.model} · ${an.features.length} features per IP per ${an.window_minutes}-min window · ${an.note}`);
    }
  } catch (error) { toast(`Model cards unavailable: ${error.message}`); }
}

function renderAnomalies(data) {
  setText('anomaly-headline', data.anomalous ? `${data.anomalous} anomalous sign-in window${data.anomalous > 1 ? 's' : ''} detected` : 'No anomalous sign-in activity');
  setText('anomaly-meta', `${data.events} sign-in events → ${data.windows_scored} IP windows scored by the Isolation Forest`);
  const list = $('#anomaly-list');
  if (!data.windows.length) { list.innerHTML = '<div class="empty-state">No sign-in telemetry yet. Sign in/out a few times, or press “Simulate attack traffic”.</div>'; return; }
  list.innerHTML = data.windows.slice(0, 12).map((w) => `<div class="anomaly-row ${w.anomalous ? 'flag' : ''}">
    <div class="an-score"><div class="cmp-track"><i style="width:${Math.round(w.score * 100)}%"></i></div><b>${w.score.toFixed(2)}</b></div>
    <div class="an-main"><b>${w.anomalous ? escapeHtml(w.pattern) : 'Normal activity'}</b><span><code>${escapeHtml(w.ip)}</code> · ${escapeHtml(w.window_start.slice(11, 16))} · ${w.attempts} attempts · ${w.accounts} account${w.accounts > 1 ? 's' : ''} · ${w.failures} failed${w.simulated ? ' · <em>simulated</em>' : ''}</span>
    ${w.reasons.length ? `<small>${w.reasons.map(escapeHtml).join(' · ')}</small>` : ''}</div></div>`).join('');
}
async function loadAnomalies() {
  if (!state.auth || !['admin', 'analyst'].includes(state.auth.role)) { setText('anomaly-headline', 'Sign in as admin or analyst to view sign-in anomalies.'); $('#anomaly-list').innerHTML = ''; return; }
  try { renderAnomalies(await api('/api/ai/anomalies?hours=24')); } catch (error) { setText('anomaly-headline', error.message); }
}
$('#anomaly-simulate')?.addEventListener('click', async () => {
  const b = $('#anomaly-simulate'); setBusy(b, true, 'Simulating…');
  try { renderAnomalies(await api('/api/ai/anomalies/simulate', { method: 'POST', body: JSON.stringify({}) })); toast('Injected labelled simulated traffic: normal users + stuffing, brute force and enumeration.'); }
  catch (error) { toast(error.message); } finally { setBusy(b, false); }
});
$('#anomaly-clear')?.addEventListener('click', async () => {
  try { const r = await api('/api/ai/anomalies/simulated', { method: 'DELETE', body: JSON.stringify({}) }); toast(`Removed ${r.deleted} simulated events.`); loadAnomalies(); } catch (error) { toast(error.message); }
});

function chatAppend(role, html) {
  const chat = $('#copilot-chat'); chat.querySelector('.chat-empty')?.remove();
  chat.insertAdjacentHTML('beforeend', `<div class="msg ${role}">${html}</div>`);
  chat.scrollTop = chat.scrollHeight;
}
async function askCopilot(question) {
  if (!state.auth) { openAuth('signin'); return; }
  chatAppend('user', escapeHtml(question));
  chatAppend('bot pending', '<span class="ai-loading">Thinking with tools…</span>');
  try {
    const r = await api('/api/ai/copilot', { method: 'POST', body: JSON.stringify({ question }) });
    $('#copilot-chat .msg.pending')?.remove();
    const tools = r.tool_calls.map((c) => `${c.tool}(${Object.entries(c.args || {}).map(([k, v]) => `${k}=${v}`).join(', ')})`).join(' → ');
    chatAppend('bot', `<div class="md">${renderMarkdown(r.answer)}</div><div class="msg-meta"><span class="mode-chip">${escapeHtml(r.mode)}</span>${tools ? `<span>tools: <code>${escapeHtml(tools)}</code></span>` : ''}</div>`);
  } catch (error) { $('#copilot-chat .msg.pending')?.remove(); chatAppend('bot', `<span class="bad">${escapeHtml(error.message)}</span>`); }
}
$('#copilot-form')?.addEventListener('submit', (e) => { e.preventDefault(); const q = $('#copilot-q').value.trim(); if (q) { $('#copilot-q').value = ''; askCopilot(q); } });
$$('#copilot-suggestions button').forEach((b) => b.addEventListener('click', () => askCopilot(b.textContent)));

let lastReport = '';
$('#report-generate')?.addEventListener('click', async () => {
  if (!state.auth) { openAuth('signin'); return; }
  const b = $('#report-generate'); setBusy(b, true, 'Writing…');
  try {
    const r = await api('/api/ai/incident-report', { method: 'POST', body: JSON.stringify({}) });
    lastReport = r.markdown;
    $('#report-view').innerHTML = `<div class="msg-meta"><span class="mode-chip">${escapeHtml(r.mode)}</span></div>${renderMarkdown(r.markdown)}`;
    $('#report-download').classList.remove('hidden');
  } catch (error) { $('#report-view').innerHTML = `<div class="auth-status show bad">${escapeHtml(error.message)}</div>`; }
  finally { setBusy(b, false); }
});
$('#report-download')?.addEventListener('click', () => {
  const blob = new Blob([lastReport], { type: 'text/markdown' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `privpass-incident-report-${new Date().toISOString().slice(0, 10)}.md`; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

async function loadAiLab() {
  try {
    const st = await api('/api/ai/status');
    setText('ai-provider', st.provider === 'anthropic' ? 'Claude connected' : 'Offline AI mode');
    setText('ai-model', st.provider === 'anthropic' ? st.model : 'set ANTHROPIC_API_KEY to enable Claude');
    $('#ai-status')?.classList.toggle('online', st.provider === 'anthropic');
  } catch {}
  loadModelCards();
  loadAnomalies();
}
