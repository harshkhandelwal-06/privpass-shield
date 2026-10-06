/*! <privpass-password-field> — drop-in breached-password protection for any signup or reset form.
 *
 *   <script src="https://YOUR-PRIVPASS-HOST/static/widget/privpass-password-field.js" defer></script>
 *   <form> … <privpass-password-field name="password" username-field="#email"></privpass-password-field> … </form>
 *
 * - Form-associated custom element: the form will not submit until the password passes.
 * - NIST SP 800-63B: 15+ chars (configurable `min-length`), no composition rules, NFKC normalisation,
 *   blocklist = offline 1M leaked-password corpus + live HIBP range check (k-anonymity, padded),
 *   context words (username, `context-words`).
 * - The password never leaves the page: the corpus check is fully local and HIBP only receives a
 *   5-character SHA-1 prefix. Fail-closed by default (`fail-open` attribute to relax).
 * - Events: `privpass-status` {valid, breached, reasons, score, mode}.
 */
(function () {
  'use strict';
  if (customElements.get('privpass-password-field')) return;
  const SCRIPT_ORIGIN = (() => { try { return new URL(document.currentScript.src).origin; } catch { return location.origin; } })();
  const corpusCache = new Map();

  async function sha1(text) { return new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text))); }
  const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('').toUpperCase();

  function loadCorpus(base) {
    if (!corpusCache.has(base)) {
      corpusCache.set(base, Promise.all([fetch(`${base}/top1m.json`).then((r) => r.json()), fetch(`${base}/top1m.bloom`).then((r) => r.arrayBuffer())])
        .then(([meta, buf]) => ({ meta, bits: new Uint8Array(buf) })).catch(() => null));
    }
    return corpusCache.get(base);
  }
  async function inCorpus(base, pw) {
    const c = await loadCorpus(base); if (!c) return null;
    const d = new DataView((await sha1(pw)).buffer); const h1 = d.getUint32(0); const h2 = (d.getUint32(4) | 1) >>> 0;
    for (let i = 0; i < c.meta.k; i++) { const idx = (h1 + i * h2) % c.meta.m; if (!(c.bits[idx >> 3] & (1 << (idx & 7)))) return false; }
    return true;
  }
  async function hibp(pw) {
    const h = hex(await sha1(pw));
    try {
      const r = await fetch(`https://api.pwnedpasswords.com/range/${h.slice(0, 5)}`, { headers: { 'Add-Padding': 'true' } });
      if (!r.ok) throw new Error();
      for (const line of (await r.text()).split(/\r?\n/)) { const [s, c] = line.trim().split(':'); if (s === h.slice(5) && Number(c) > 0) return { status: 'breached', count: Number(c) }; }
      return { status: 'safe' };
    } catch { return { status: 'unavailable' }; }
  }

  const CSS = `
    :host{display:block;font:inherit;--pp-accent:#0c9f84;--pp-bad:#c9344f;--pp-warn:#a96f00;--pp-border:rgba(0,0,0,.18);--pp-muted:#5f6b6b;--pp-bg:#fff}
    .row{display:flex;gap:6px}input{flex:1;min-width:0;font:inherit;padding:11px 12px;border:1px solid var(--pp-border);border-radius:10px;background:var(--pp-bg);color:inherit}
    input:focus{outline:2px solid var(--pp-accent);outline-offset:1px}button{font:inherit;border:1px solid var(--pp-border);border-radius:10px;background:var(--pp-bg);padding:0 12px;cursor:pointer;color:inherit}
    .meter{height:5px;border-radius:9px;background:rgba(0,0,0,.08);margin-top:8px;overflow:hidden}.meter i{display:block;height:100%;width:0;background:var(--pp-bad);transition:width .3s,background .3s}
    ul{list-style:none;padding:0;margin:8px 0 0;display:grid;gap:3px;font-size:12.5px;color:var(--pp-muted)}li::before{content:"○ ";}li.ok{color:inherit}li.ok::before{content:"● ";color:var(--pp-accent)}li.bad{color:var(--pp-bad)}li.bad::before{content:"✕ ";}
    .status{font-size:12.5px;margin-top:6px;min-height:1.2em}.status.bad{color:var(--pp-bad)}.status.good{color:var(--pp-accent)}.status.warn{color:var(--pp-warn)}
    .brand{font-size:11px;color:var(--pp-muted);margin-top:6px}.brand b{color:var(--pp-accent)}`;

  class PrivPassPasswordField extends HTMLElement {
    static formAssociated = true;
    static get observedAttributes() { return ['min-length']; }
    constructor() {
      super();
      this.internals = this.attachInternals();
      const root = this.attachShadow({ mode: 'open', delegatesFocus: true });
      root.innerHTML = `<style>${CSS}</style><div class="row"><input part="input" type="password" autocomplete="new-password" aria-describedby="st"/><button type="button" aria-label="Show password">👁</button></div>
        <div class="meter"><i></i></div><ul><li data-r="len"></li><li data-r="ctx">Doesn't contain your username</li><li data-r="corpus">Not in the top 1 million leaked passwords</li><li data-r="hibp">Not found in known breaches (Have I Been Pwned)</li></ul>
        <div class="status" id="st" role="status" aria-live="polite"></div><div class="brand">Protected by <b>PrivPass Shield</b> · your password never leaves this page</div>`;
      this.input = root.querySelector('input'); this.state = { valid: false, seq: 0 };
      root.querySelector('button').addEventListener('click', () => { this.input.type = this.input.type === 'password' ? 'text' : 'password'; });
      this.input.addEventListener('input', () => this.schedule());
      this.update('');
    }
    get minLength() { return Number(this.getAttribute('min-length') || 15); }
    get value() { return this.input.value; }
    get valid() { return this.state.valid; }
    connectedCallback() {
      this.shadowRoot.querySelector('[data-r="len"]').textContent = `At least ${this.minLength} characters`;
      if (this.hasAttribute('placeholder')) this.input.placeholder = this.getAttribute('placeholder');
      loadCorpus(this.getAttribute('corpus-src') || `${SCRIPT_ORIGIN}/static/breach`);
      const uf = this.getAttribute('username-field'); if (uf) document.querySelector(uf)?.addEventListener('input', () => this.schedule());
    }
    formResetCallback() { this.input.value = ''; this.update(''); }
    schedule() { clearTimeout(this.timer); this.update(this.input.value, true); this.timer = setTimeout(() => this.check(), 350); }
    mark(rule, state) { const li = this.shadowRoot.querySelector(`[data-r="${rule}"]`); li.classList.toggle('ok', state === true); li.classList.toggle('bad', state === false); }
    say(cls, text) { const s = this.shadowRoot.getElementById('st'); s.className = `status ${cls}`; s.textContent = text; }
    setValid(ok, message) {
      this.state.valid = ok;
      this.internals.setFormValue(this.input.value);
      if (ok) this.internals.setValidity({}); else this.internals.setValidity({ customError: true }, message || 'Choose a different password', this.input);
    }
    update(pw, pending = false) {
      const n = [...pw.normalize('NFKC')].length;
      this.mark('len', pw ? n >= this.minLength : null);
      let score = Math.min(100, Math.round((n / (this.minLength + 5)) * 70));
      const meter = this.shadowRoot.querySelector('.meter i'); meter.style.width = `${pw ? score : 0}%`; meter.style.background = score > 75 ? 'var(--pp-accent)' : score > 45 ? 'var(--pp-warn)' : 'var(--pp-bad)';
      if (pending) { this.mark('corpus', null); this.mark('hibp', null); }
      this.setValid(false, pw ? 'Checking password…' : 'Enter a password');
    }
    async check() {
      const seq = ++this.state.seq; const raw = this.input.value; const pw = raw.normalize('NFKC');
      const reasons = []; const emit = (valid, breached, mode) => this.dispatchEvent(new CustomEvent('privpass-status', { bubbles: true, composed: true, detail: { valid, breached, reasons, mode } }));
      if (!pw) { this.say('', ''); return; }
      const uname = (document.querySelector(this.getAttribute('username-field') || '#__none')?.value || '').split('@')[0].toLowerCase();
      const words = [uname, ...(this.getAttribute('context-words') || '').split(',')].map((w) => w.trim().toLowerCase()).filter((w) => w.length >= 4);
      const ctxHit = words.some((w) => pw.toLowerCase().includes(w));
      this.mark('ctx', !ctxHit);
      if ([...pw].length < this.minLength) reasons.push(`Use at least ${this.minLength} characters`);
      if (ctxHit) reasons.push('Do not include your username or the site name');
      const local = await inCorpus(this.getAttribute('corpus-src') || `${SCRIPT_ORIGIN}/static/breach`, pw);
      if (seq !== this.state.seq) return;
      this.mark('corpus', local === null ? null : !local);
      if (local) { reasons.push('This is one of the 1 million most-leaked passwords'); this.say('bad', reasons[0]); this.setValid(false, reasons[0]); emit(false, true, 'local'); return; }
      if (reasons.length) { this.say('warn', reasons[0]); this.setValid(false, reasons[0]); emit(false, false, 'policy'); return; }
      this.say('', 'Checking known breaches (only 5 characters of a hash leave this page)…');
      const r = await hibp(pw);
      if (seq !== this.state.seq) return;
      if (r.status === 'breached') { this.mark('hibp', false); const m = `Found in ${r.count.toLocaleString()} breached accounts — choose another`; reasons.push(m); this.say('bad', m); this.setValid(false, m); emit(false, true, 'hibp'); return; }
      if (r.status === 'unavailable' && !this.hasAttribute('fail-open')) { this.mark('hibp', null); const m = 'Breach check unavailable — try again in a moment'; this.say('warn', m); this.setValid(false, m); emit(false, false, 'unavailable'); return; }
      this.mark('hibp', r.status === 'safe' ? true : null);
      this.say('good', 'Strong choice — not found in any known breach.');
      this.setValid(true); emit(true, false, r.status === 'safe' ? 'hibp' : 'local');
    }
  }
  customElements.define('privpass-password-field', PrivPassPasswordField);
})();
