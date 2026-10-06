// PrivPass Shield — word & name guessing model (runs in the browser; the password never leaves this tab).
//
// Why: the neural model learned from leaked passwords, so a rare surname looks "unusual" to it and gets a huge
// guess count. Real attackers don't guess letter by letter: they combine ranked word lists and name lists
// (first names + surnames from many countries), add capitals, leetspeak, years and separators. This model
// estimates how many guesses that attack needs, zxcvbn-style: the cheapest way to build the password from
//   • dictionary tokens  (rank in a 103k word + first-name + surname list)
//   • name-like tokens   (pronounceable words that aren't in the list — still in bigger name dictionaries)
//   • years, digit runs, sequences, repeats, separators and symbols
//   • brute force for anything else
// PrivPassGuess.estimate() then takes the most conservative of: this model, the neural model and the
// offline breach corpus, so the displayed guesses and crack time always agree with the score.
(function () {
  const LOG2 = Math.log10(2);
  let dictPromise = null;

  async function loadDict() {
    if (!dictPromise) {
      dictPromise = (async () => {
        try {
          if (typeof DecompressionStream === 'undefined') return new Map();
          const res = await fetch('/static/ml/words-names.txt.gz', { credentials: 'same-origin' });
          if (!res.ok) return new Map();
          const text = await new Response(res.body.pipeThrough(new DecompressionStream('gzip'))).text();
          const map = new Map();
          text.split('\n').forEach((w, i) => { if (w && !map.has(w)) map.set(w, i + 1); });
          return map;
        } catch { return new Map(); }
      })();
    }
    return dictPromise;
  }

  const LEET = { '@': 'a', '4': 'a', '8': 'b', '(': 'c', '3': 'e', '6': 'g', '1': 'i', '!': 'i', '|': 'l', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't', '2': 'z' };
  const isLetter = (c) => /\p{L}/u.test(c);
  const isDigit = (c) => c >= '0' && c <= '9';
  const VOWELS = /[aeiouy]/;

  function caseCost(tok) {
    const letters = [...tok].filter(isLetter);
    const up = letters.filter((c) => c !== c.toLowerCase()).length;
    if (!up) return 0;
    if (up === letters.length || (up === 1 && tok[0] !== tok[0].toLowerCase())) return LOG2;   // ALL CAPS or Capitalised
    let c = 1, n = letters.length; for (let k = 1; k <= up; k++) c = c * (n - k + 1) / k;      // arbitrary mixed case
    return Math.log10(Math.max(2, c));
  }

  // A token that looks like a word or a name (pronounceable) is found in larger name/word lists.
  function nameLike(low) {
    if (low.length < 4 || low.length > 12 || !/^\p{L}+$/u.test(low)) return false;
    const v = [...low].filter((c) => VOWELS.test(c)).length / low.length;
    if (v < 0.2 || v > 0.7) return false;
    return !/[^aeiouy]{4,}/.test(low) && !/(.)\1\1/.test(low);
  }

  function digitCost(run) {
    const n = run.length;
    const num = Number(run);
    if (n === 4 && num >= 1900 && num <= 2039) return Math.log10(140);                         // a year
    if (n === 2) return 2;
    if (/^(\d)\1+$/.test(run)) return Math.log10(10 * n);                                       // 1111
    const asc = '01234567890123456789', desc = '98765432109876543210';
    if (n >= 3 && (asc.includes(run) || desc.includes(run))) return Math.log10(20 * n);         // 1234 / 4321
    if (n === 6 || n === 8) {                                                                   // ddmmyy / ddmmyyyy dates
      const dd = +run.slice(0, 2), mm = +run.slice(2, 4);
      if (dd >= 1 && dd <= 31 && mm >= 1 && mm <= 12) return Math.log10(n === 6 ? 36600 : 365 * 140);
    }
    return n;                                                                                   // brute force
  }

  function symbolCost(c) { return ' -_.@!#*$&+'.includes(c) ? 1 : Math.log10(33); }
  function bruteCost(c) { return isDigit(c) ? 1 : isLetter(c) ? Math.log10(26) + (c !== c.toLowerCase() ? 0.1 : 0) : Math.log10(33); }

  // Cheapest segmentation (dynamic programming over positions). Each segment adds a small template cost.
  function estimateWith(dict, password, userInputs = []) {
    const pw = String(password || '').normalize('NFKC');
    // Targeted attack: the person's own name, email and company are the first things tried.
    const personal = new Map();
    userInputs.flatMap((v) => String(v || '').toLowerCase().normalize('NFKC').split(/[^\p{L}\p{N}]+/u))
      .filter((t) => t.length >= 3).forEach((t, i) => { if (!personal.has(t)) personal.set(t, i + 1); });
    const chars = [...pw];
    const n = chars.length;
    if (!n) return null;
    const SEG = 0.35;
    const best = new Array(n + 1).fill(Infinity); const back = new Array(n + 1).fill(null);
    best[0] = 0;
    for (let i = 0; i < n; i++) {
      if (best[i] === Infinity) continue;
      const relax = (j, cost, kind, tok) => { const v = best[i] + cost + SEG; if (v < best[j]) { best[j] = v; back[j] = { i, kind, tok, cost }; } };
      // brute force one character
      relax(i + 1, bruteCost(chars[i]), 'brute', chars[i]);
      // symbol / separator
      if (!isLetter(chars[i]) && !isDigit(chars[i])) relax(i + 1, symbolCost(chars[i]), 'symbol', chars[i]);
      // digit run
      if (isDigit(chars[i])) {
        let j = i; while (j < n && isDigit(chars[j])) j++;
        for (let k = i + 1; k <= j; k++) relax(k, digitCost(chars.slice(i, k).join('')), 'digits', chars.slice(i, k).join(''));
      }
      // dictionary / name tokens (with leetspeak), up to 20 characters
      for (let j = i + 2; j <= Math.min(n, i + 20); j++) {
        const raw = chars.slice(i, j).join('');
        let subs = 0;
        const low = [...raw].map((c) => { if (LEET[c] && !isLetter(c)) { subs++; return LEET[c]; } return c.toLowerCase(); }).join('');
        if (!/^\p{L}+$/u.test(low)) continue;
        // Leetspeak only counts inside a real dictionary word, for a few characters, never at the start.
        if (subs && (subs > Math.max(1, Math.floor(raw.length / 3)) || !isLetter(raw[0]))) continue;
        const leet = subs ? subs * LOG2 + 0.3 : 0;
        const rank = personal.has(low) ? personal.get(low) : dict.get(low);
        if (rank) relax(j, Math.log10(rank + 1) + caseCost(raw) + leet, personal.has(low) ? 'personal' : 'word', raw);
        else if (!subs && nameLike(low)) relax(j, Math.min(3.8 + 0.35 * low.length, 8) + caseCost(raw), 'name-like', raw);
      }
      // reuse of a chunk that already appeared earlier (e.g. divy1023divy1032)
      for (let j = i + 3; j <= Math.min(n, i + 20); j++) {
        const raw = chars.slice(i, j).join('');
        if (chars.slice(0, i).join('').toLowerCase().includes(raw.toLowerCase())) relax(j, LOG2 + 0.5, 'reuse', raw);
      }
      // repeat of the previous chunk (e.g. abcabc)
      for (let len = 1; len <= Math.floor((n - i) / 2) && len <= 12; len++) {
        if (i >= len && chars.slice(i - len, i).join('') === chars.slice(i, i + len).join('')) relax(i + len, LOG2, 'repeat', chars.slice(i, i + len).join(''));
      }
    }
    const parts = []; let j = n;
    while (j > 0 && back[j]) { parts.unshift(back[j]); j = back[j].i; }
    const segs = parts.length;
    let fact = 0; for (let k = 2; k <= segs; k++) fact += Math.log10(k);
    const log10 = Math.max(0, best[n] - SEG * segs + Math.min(fact, SEG * segs) + Math.log10(Math.max(1, segs)));
    return {
      log10Guesses: Math.round(log10 * 100) / 100,
      parts: parts.map((p) => ({ kind: p.kind, token: p.tok, log10: Math.round(p.cost * 100) / 100 })),
      words: parts.filter((p) => ['word', 'name-like', 'personal'].includes(p.kind)).map((p) => p.tok),
      personal: parts.some((p) => p.kind === 'personal'),
    };
  }

  async function estimate(password, userInputs = []) {
    const dict = await loadDict();
    return estimateWith(dict, password, userInputs);
  }

  function crackTime(log10) {
    if (window.PrivPassNeural?.crackTime) return window.PrivPassNeural.crackTime(log10);
    const secs = Math.pow(10, log10) / 1e10;
    return secs < 1 ? 'instantly' : `${Math.round(secs)} seconds`;
  }
  const scoreOf = (log10) => Math.max(0, Math.min(100, Math.round((log10 - 3) * 6.5)));   // same scale as the neural score

  // The conservative combination shown everywhere in the UI.
  async function combined(password, userInputs = []) {
    const pw = String(password || '');
    if (!pw) return null;
    const [nn, st, inCorpus] = await Promise.all([
      window.PrivPassNeural ? window.PrivPassNeural.estimate(pw).catch(() => null) : null,
      estimate(pw, userInputs).catch(() => null),
      window.PrivPassBloom ? window.PrivPassBloom.check(pw).catch(() => null) : null,
    ]);
    const candidates = [];
    if (nn) candidates.push({ source: 'neural model', log10: nn.log10Guesses });
    if (st) candidates.push({ source: st.personal ? 'targeted guess (your name/company)' : st.words.length ? 'word & name lists' : 'pattern model', log10: st.log10Guesses });
    if (inCorpus) candidates.push({ source: 'leaked-password list', log10: 6 });
    if (!candidates.length) return null;
    const win = candidates.reduce((a, b) => (b.log10 < a.log10 ? b : a));
    return { log10Guesses: win.log10, score: scoreOf(win.log10), crackTime: crackTime(win.log10), driver: win.source,
             neural: nn, structure: st, inCorpus: !!inCorpus };
  }

  window.PrivPassStructure = { estimate, estimateWith, loadDict, scoreOf };
  window.PrivPassGuess = { estimate: combined };
})();
