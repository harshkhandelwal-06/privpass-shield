// PrivPass neural password-guessability model - runs entirely in the browser.
// A character-level GRU (trained on a public leaked-password frequency list) gives P(password);
// a Monte Carlo calibration table turns that probability into an estimated guess number.
// Nothing about the password is ever sent anywhere: this file only does arithmetic locally.
(function () {
  'use strict';
  let modelPromise = null;

  function dequant(q) {
    const bin = atob(q.data);
    const out = new Float32Array(bin.length);
    for (let i = 0; i < bin.length; i++) { const b = bin.charCodeAt(i); out[i] = (b > 127 ? b - 256 : b) * q.scale; }
    return { data: out, rows: q.shape[0], cols: q.shape[1] };
  }

  async function load() {
    if (!modelPromise) {
      modelPromise = fetch('/static/ml/password-model.json', { credentials: 'same-origin' })
        .then((r) => { if (!r.ok) throw new Error('model unavailable'); return r.json(); })
        .then((m) => {
          const w = m.weights;
          return {
            meta: m, H: m.hidden, emb: dequant(w.emb), wih: dequant(w.w_ih), whh: dequant(w.w_hh), wout: dequant(w.w_out),
            bih: Float32Array.from(w.b_ih), bhh: Float32Array.from(w.b_hh), bout: Float32Array.from(w.b_out), table: m.calibration,
          };
        })
        .catch((e) => { modelPromise = null; throw e; });
    }
    return modelPromise;
  }

  const sig = (x) => 1 / (1 + Math.exp(-x));

  function matvec(M, v, bias) {
    const out = new Float32Array(M.rows);
    for (let r = 0; r < M.rows; r++) {
      let s = bias ? bias[r] : 0; const off = r * M.cols;
      for (let c = 0; c < M.cols; c++) s += M.data[off + c] * v[c];
      out[r] = s;
    }
    return out;
  }

  function encode(m, pw) {
    const sp = m.meta.special; const ids = [sp.bos];
    for (const ch of pw.slice(0, m.meta.max_len)) {
      const code = ch.codePointAt(0);
      ids.push(code >= 32 && code < 127 ? code - m.meta.first_char + m.meta.vocab_offset : sp.unk);
    }
    ids.push(sp.eos);
    return ids;
  }

  function log2prob(m, pw) {
    const H = m.H; let h = new Float32Array(H); let total = 0;
    const ids = encode(m, pw); const sp = m.meta.special;
    for (let t = 0; t + 1 < ids.length; t++) {
      const x = m.emb.data.subarray(ids[t] * m.emb.cols, (ids[t] + 1) * m.emb.cols);
      const gi = matvec(m.wih, x, m.bih); const gh = matvec(m.whh, h, m.bhh);
      const nh = new Float32Array(H);
      for (let i = 0; i < H; i++) {
        const r = sig(gi[i] + gh[i]); const z = sig(gi[H + i] + gh[H + i]);
        const n = Math.tanh(gi[2 * H + i] + r * gh[2 * H + i]);
        nh[i] = (1 - z) * n + z * h[i];
      }
      h = nh;
      const logits = matvec(m.wout, h, m.bout);
      logits[sp.pad] = -1e9; logits[sp.bos] = -1e9; logits[sp.unk] = -1e9;
      let mx = -Infinity; for (const v of logits) mx = Math.max(mx, v);
      let z = 0; for (const v of logits) z += Math.exp(v - mx);
      total += (logits[ids[t + 1]] - mx - Math.log(z)) / Math.LN2;
    }
    return total;
  }

  function guessesFromTable(table, lp2) {
    if (lp2 >= table[0][0]) return 0;
    for (let i = 0; i + 1 < table.length; i++) {
      const [aLp, aG] = table[i]; const [bLp, bG] = table[i + 1];
      if (bLp <= lp2 && lp2 <= aLp) return aG + ((aLp - lp2) / Math.max(1e-9, aLp - bLp)) * (bG - aG);
    }
    const [lastLp, lastG] = table[table.length - 1];
    return lastG + (lastLp - lp2) * Math.log10(2);
  }

  function crackTime(log10) {
    const secs = Math.pow(10, log10) / 1e10; // offline attack, fast hash, ~10 billion guesses/second
    const units = [[31557600e9, 'billion years'], [31557600e6, 'million years'], [31557600, 'years'], [86400, 'days'], [3600, 'hours'], [60, 'minutes'], [1, 'seconds']];
    if (secs < 1) return 'instantly';
    if (secs > 31557600 * 1e6) return 'more than a million years';
    for (const [s, name] of units) if (secs >= s) { const v = secs / s; return `${v >= 100 ? Math.round(v).toLocaleString() : v.toFixed(1)} ${name}`; }
    return 'instantly';
  }

  async function estimate(password) {
    const m = await load();
    const pw = String(password || '');
    if (!pw) return null;
    const lp = log2prob(m, pw);
    const log10 = Math.max(0, guessesFromTable(m.table, lp));
    const score = Math.max(0, Math.min(100, Math.round((log10 - 3) * 6.5)));
    return { log10Guesses: Math.round(log10 * 100) / 100, log2Prob: Math.round(lp * 100) / 100, score, crackTime: crackTime(log10), card: m.meta.card };
  }

  window.PrivPassNeural = { estimate, load, crackTime };
})();
