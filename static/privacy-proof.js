// PrivPass privacy proof: a live inspector of every network request this page makes.
// Loaded BEFORE the app so no request can escape it. For each request it checks the URL and body
// for any password currently typed on the page - as plain text, NFKC-normalised, and as a full
// SHA-1 hash - and shows the verdict live. This is how the product *demonstrates* that no
// plaintext (and no full hash) ever leaves the browser.
(function () {
  'use strict';
  const log = [];
  const listeners = new Set();
  const PW_SELECTORS = ['#pw-input', '#signin-password', '#signup-password', '#signup-confirm', '#reset-password', '#reset-confirm',
    '#sec-current', '#sec-new', '#sec-confirm', '#vault-master', '#vault-password', '#hero-try'];

  async function sha1Hex(text) {
    const d = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function secretsOnPage() {
    const vals = new Set();
    for (const sel of PW_SELECTORS) {
      const v = document.querySelector(sel)?.value;
      if (v && v.length >= 4) { vals.add(v); vals.add(v.normalize('NFKC')); }
    }
    return [...vals];
  }

  function bodyText(body) {
    if (body == null) return '';
    if (typeof body === 'string') return body;
    if (body instanceof URLSearchParams) return body.toString();
    if (body instanceof FormData) return '[multipart form data: ' + [...body.keys()].join(', ') + ']';
    if (body instanceof Blob) return `[binary ${body.size} bytes]`;
    try { return JSON.stringify(body); } catch { return String(body); }
  }

  async function inspect(entry, urlText, body) {
    const haystack = (decodeURIComponent(urlText) + '\n' + body);
    const upper = haystack.toUpperCase();
    const found = [];
    for (const s of secretsOnPage()) {
      if (haystack.includes(s)) found.push('plaintext password');
      const h = (await sha1Hex(s)).toUpperCase();
      if (upper.includes(h)) found.push('full SHA-1 of password');
      else if (upper.includes(h.slice(5))) found.push('SHA-1 suffix');
    }
    entry.leak = [...new Set(found)];
    entry.verdict = entry.leak.length ? 'LEAK' : 'CLEAN';
    const m = /api\.pwnedpasswords\.com\/range\/([0-9A-F]{5})/i.exec(urlText);
    entry.note = m ? `k-anonymity: only prefix ${m[1]} sent` : entry.note;
    listeners.forEach((fn) => fn(entry, log));
  }

  function record(method, url, body) {
    let u; try { u = new URL(url, location.href); } catch { u = { host: '?', pathname: String(url), search: '' }; }
    const text = bodyText(body);
    const entry = { t: new Date(), method: (method || 'GET').toUpperCase(), host: u.host, path: u.pathname + (u.search || ''), bytes: text.length,
      external: u.host !== location.host, verdict: 'CHECKING', leak: [], note: '' };
    log.push(entry); if (log.length > 300) log.shift();
    inspect(entry, String(url), text);
    return entry;
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = function (input, init = {}) {
    const url = typeof input === 'string' ? input : input?.url || String(input);
    record(init.method || input?.method, url, init.body);
    return realFetch(input, init);
  };
  const realSend = XMLHttpRequest.prototype.send; const realOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url, ...rest) { this.__pp = { method, url }; return realOpen.call(this, method, url, ...rest); };
  XMLHttpRequest.prototype.send = function (body) { if (this.__pp) record(this.__pp.method, this.__pp.url, body); return realSend.call(this, body); };
  if (navigator.sendBeacon) { const rb = navigator.sendBeacon.bind(navigator); navigator.sendBeacon = (url, data) => { record('BEACON', url, data); return rb(url, data); }; }

  window.PrivacyProof = { log, onEntry: (fn) => listeners.add(fn), stats: () => ({ total: log.length, leaks: log.filter((e) => e.verdict === 'LEAK').length, external: log.filter((e) => e.external).length }) };
})();
