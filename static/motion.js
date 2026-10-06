// PrivPass Shield 7.0 — motion layer. Loaded last; purely presentational.
// Everything here is progressive: if this file fails, the app still works.
// Respects prefers-reduced-motion, and stays static under automation (navigator.webdriver)
// so end-to-end tests see final states instead of mid-animation frames.
(() => {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const html = document.documentElement;
  const body = document.body;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fine = matchMedia('(pointer: fine)').matches;
  const automated = navigator.webdriver === true;
  const still = reduced || automated;
  const session = {
    get(k) { try { return sessionStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch { /* storage blocked */ } },
  };
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const raf = (fn) => { let q = false; return (...a) => { if (q) return; q = true; requestAnimationFrame(() => { q = false; fn(...a); }); }; };

  if (document.startViewTransition && !still) html.classList.add('vt');

  // ------------------------------------------------------------ preloader
  (function preloader() {
    const finish = () => {
      html.classList.add('pre-done', 'loaded');
      setTimeout(() => html.classList.add('pre-skip'), 1200);
    };
    if (still || session.get('pp-pre')) { html.classList.add('pre-skip', 'loaded'); return; }
    session.set('pp-pre', '1');
    const num = $('#pre-num'); const bar = $('#pre-bar');
    const t0 = performance.now(); const D = 1350;
    const tick = (t) => {
      const p = clamp((t - t0) / D, 0, 1); const e = 1 - Math.pow(1 - p, 3);
      if (num) num.textContent = String(Math.round(e * 100)).padStart(3, '0');
      if (bar) bar.style.width = `${e * 100}%`;
      if (p < 1) requestAnimationFrame(tick); else setTimeout(finish, 180);
    };
    requestAnimationFrame(tick);
  })();

  // ------------------------------------------------------------ nav indicator
  const topnav = $('#topnav'); const indicator = $('#nav-indicator');
  const moveIndicator = raf(() => {
    if (!topnav || !indicator) return;
    const a = $('#topnav button.active');
    if (!a || !a.offsetWidth) { indicator.style.opacity = '0'; return; }
    indicator.style.width = `${a.offsetWidth}px`;
    indicator.style.transform = `translateX(${a.offsetLeft}px)`;
    indicator.style.opacity = '1';
  });
  if (topnav) {
    new MutationObserver(moveIndicator).observe(topnav, { subtree: true, attributes: true, attributeFilter: ['class'] });
    if (window.ResizeObserver) new ResizeObserver(moveIndicator).observe(topnav);
  }
  document.fonts?.ready?.then(moveIndicator);

  // ------------------------------------------------------------ full-screen menu
  const menuBtn = $('#menu-btn'); const overlay = $('#menu-overlay');
  function setMenu(open) {
    body.classList.toggle('menu-open', open);
    menuBtn?.setAttribute('aria-expanded', String(open));
    overlay?.setAttribute('aria-hidden', String(!open));
    html.style.overflow = open ? 'hidden' : '';
    if (open) $('#topbar')?.classList.remove('hide');
  }
  menuBtn?.addEventListener('click', () => setMenu(!body.classList.contains('menu-open')));
  overlay?.addEventListener('click', (e) => { if (e.target.closest('.menu-link')) setMenu(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && body.classList.contains('menu-open')) setMenu(false); });
  matchMedia('(min-width: 1241px)').addEventListener?.('change', (m) => { if (m.matches) setMenu(false); });

  // ------------------------------------------------------------ header hide + scroll progress
  const topbar = $('#topbar'); const progress = $('#scroll-progress');
  let lastY = scrollY;
  const onScroll = raf(() => {
    const y = scrollY;
    const dropdownOpen = $('.account-menu.open, .bell.open');
    if (topbar && !still) topbar.classList.toggle('hide', y > lastY && y > 260 && !dropdownOpen && !body.classList.contains('menu-open'));
    lastY = y;
    const max = document.documentElement.scrollHeight - innerHeight;
    if (progress) progress.style.transform = `scaleX(${max > 0 ? clamp(y / max, 0, 1) : 0})`;
    storyScroll();
  });
  addEventListener('scroll', onScroll, { passive: true });
  // bring the header back when the pointer heads for it or keyboard focus lands in it
  addEventListener('pointermove', (e) => { if (e.clientY < 90) topbar?.classList.remove('hide'); }, { passive: true });
  topbar?.addEventListener('focusin', () => topbar.classList.remove('hide'));

  // ------------------------------------------------------------ split text
  let splitCounter = 0;
  function splitWords(el) {
    if (el.dataset.splitDone) return;
    el.dataset.splitDone = '1';
    el.classList.add('split-target');
    splitCounter = 0;
    const walk = (node) => {
      [...node.childNodes].forEach((child) => {
        if (child.nodeType === 3) {
          const parts = child.textContent.split(/(\s+)/);
          const frag = document.createDocumentFragment();
          parts.forEach((part) => {
            if (!part) return;
            if (/^\s+$/.test(part)) { frag.appendChild(document.createTextNode(part)); return; }
            const w = document.createElement('span'); w.className = 'w';
            const inner = document.createElement('span'); inner.textContent = part; inner.style.setProperty('--i', splitCounter++);
            w.appendChild(inner); frag.appendChild(w);
          });
          child.replaceWith(frag);
        } else if (child.nodeType === 1) walk(child);
      });
    };
    walk(el);
  }

  // ------------------------------------------------------------ reveal on scroll
  const REVEAL = ['.section-head > *', '.panel', '.glass-xl', '.glass', '.metric', '.brief-card', '.bento-card', '.num', '.case-card',
    '.incident-summary-row > div', '.sec-label', '.finale .hero-cta', '.marquee', '.story-copy', '.story-visual'].join(',');
  let batch = [];
  const flush = raf(() => { batch.forEach((el, i) => { el.style.setProperty('--d', `${Math.min(i, 6) * 0.07}s`); el.classList.add('in'); }); batch = []; });
  const io = still ? null : new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      io.unobserve(e.target);
      if (e.target.classList.contains('split-target')) e.target.classList.add('split-in');
      if (e.target.classList.contains('rv')) batch.push(e.target);
      countStatic(e.target);
    });
    flush();
  }, { rootMargin: '0px 0px -6% 0px', threshold: 0 });

  function prepare(root) {
    const heads = $$('.section-head h2, [data-split]', root);
    heads.forEach((h) => { if (!still) { splitWords(h); io.observe(h); } });
    if (still) { $$('.num b[data-count]', root).forEach(countStatic); return; }
    $$(REVEAL, root).forEach((el) => {
      if (el.dataset.rvp || el.closest('.modal, .proof-drawer, .tour, .hero, .story-sticky .story-copy .sec-label')) return;
      if (el.parentElement?.closest('.rv')) return;
      el.dataset.rvp = '1'; el.classList.add('rv'); io.observe(el);
    });
    $$('.num', root).forEach((n) => io.observe(n));
  }

  // tour: show everything immediately so the spotlight measures final positions
  const tour = $('#tour');
  if (tour) new MutationObserver(() => {
    const on = !tour.classList.contains('hidden');
    html.classList.toggle('tour-on', on);
    if (on) $$('.rv').forEach((el) => el.classList.add('in'));
  }).observe(tour, { attributes: true, attributeFilter: ['class'] });

  // ------------------------------------------------------------ count-up numbers
  function animateNumber(el, to, { dec = 0, prefix = '', suffix = '', dur = 1400 } = {}) {
    const t0 = performance.now();
    const step = (t) => {
      const p = clamp((t - t0) / dur, 0, 1); const e = p === 1 ? 1 : 1 - Math.pow(2, -10 * p);
      const v = (to * e).toFixed(dec);
      el._written = prefix + (dec ? v : Number(v).toLocaleString()) + suffix;
      el.textContent = el._written;
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  function countStatic(el) {
    const b = el.matches?.('b[data-count]') ? el : el.querySelector?.('b[data-count]');
    if (!b || b._done) return; b._done = true;
    const to = Number(b.dataset.count); const dec = Number(b.dataset.dec || 0); const suffix = b.dataset.suffix || '';
    if (still) { b.textContent = to.toFixed(dec) + suffix; return; }
    animateNumber(b, to, { dec, suffix, dur: 1800 });
  }
  const LIVE_COUNT = ['#m-checks', '#m-breach', '#m-secrets', '#admin-breach', '#admin-secrets', '#admin-avg', '#admin-posture', '#crit-count', '#high-count', '#med-count',
    '#incident-count-detected', '#incident-count-triaged', '#incident-count-contained', '#incident-count-rotated', '#incident-count-verified',
    '#graph-blast', '#vault-count', '#sla-compliance', '#honey-trips', '#sla-overdue'];
  if (!still) {
    const mo = new MutationObserver((muts) => {
      const seen = new Set();
      muts.forEach((m) => { const el = m.target.nodeType === 1 ? m.target : m.target.parentElement; if (el) seen.add(el.closest('[data-countup]') || el); });
      seen.forEach((el) => {
        const txt = el.textContent.trim();
        if (txt === el._written) return;
        const m = txt.match(/^([^\d-]*)(-?\d[\d,]*(?:\.\d+)?)(.*)$/);
        if (!m) return;
        const num = Number(m[2].replace(/,/g, '')); if (!Number.isFinite(num) || num === 0) return;
        const dec = (m[2].split('.')[1] || '').length;
        animateNumber(el, num, { dec, prefix: m[1], suffix: m[3], dur: 1200 });
      });
    });
    LIVE_COUNT.forEach((s) => { const el = $(s); if (el) { el.setAttribute('data-countup', ''); mo.observe(el, { childList: true, characterData: true, subtree: true }); } });
  }

  // ------------------------------------------------------------ view transitions around nav()
  function afterNav() {
    const active = $('.view.active');
    const name = active?.id?.replace('view-', '');
    if (name) $$('[data-nav]').forEach((b) => b.classList.toggle('active', b.dataset.nav === name));
    body.classList.toggle('on-overview', active?.id === 'view-overview');
    moveIndicator(); setMenu(false); storyScroll();
  }
  if (typeof window.nav === 'function') {
    const baseNav = window.nav;
    window.nav = function (name) {
      const same = $('.view.active')?.id === `view-${name}`;
      if (html.classList.contains('vt') && !same && !document.hidden) {
        const t = document.startViewTransition(() => baseNav(name));
        t.updateCallbackDone.then(afterNav, afterNav);
      } else { baseNav(name); afterNav(); }
    };
  }

  // ------------------------------------------------------------ cursor
  if (fine && !still) {
    html.classList.add('has-cursor');
    const cur = $('#cursor'); const ring = $('.cursor-ring', cur); const dot = $('.cursor-dot', cur); const label = $('#cursor-label');
    let x = innerWidth / 2; let y = innerHeight / 2; let rx = x; let ry = y;
    addEventListener('pointermove', (e) => {
      x = e.clientX; y = e.clientY; cur.classList.remove('is-hidden');
      const t = e.target instanceof Element ? e.target : null;
      const lab = t?.closest('[data-cursor]');
      const txt = !lab && t?.closest('input:not([type="range"]):not([type="checkbox"]):not([type="file"]), textarea');
      const hov = !lab && !txt && t?.closest('a, button, [role="button"], summary, select, label, .scenario');
      cur.classList.toggle('is-label', !!lab); cur.classList.toggle('is-text', !!txt); cur.classList.toggle('is-hover', !!hov);
      if (lab && label.textContent !== lab.dataset.cursor) label.textContent = lab.dataset.cursor;
    }, { passive: true });
    document.addEventListener('pointerleave', () => cur.classList.add('is-hidden'));
    const loop = () => {
      rx += (x - rx) * 0.2; ry += (y - ry) * 0.2;
      dot.style.transform = `translate3d(${x}px,${y}px,0)`;
      ring.style.transform = `translate3d(${rx}px,${ry}px,0)`;
      requestAnimationFrame(loop);
    };
    loop();
  }
  $$('.brief-card, .bento-card').forEach((el) => { el.dataset.cursor = el.id === 'bento-proof' ? 'Watch' : 'Open'; });
  const dz = $('#dropzone'); if (dz) dz.dataset.cursor = 'Drop ZIP';

  // ------------------------------------------------------------ magnetic buttons + card spotlight
  if (fine && !still) {
    $$('.magnetic').forEach((el) => {
      el.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect();
        el.style.transform = `translate(${(e.clientX - r.left - r.width / 2) * 0.22}px,${(e.clientY - r.top - r.height / 2) * 0.32}px)`;
      });
      el.addEventListener('pointerleave', () => { el.style.transform = ''; });
    });
    $$('.panel, .glass-xl, .bento-card, .brief-card:not(.inverse)').forEach((el) => el.classList.add('spot'));
    const spot = raf((e) => {
      const card = e.target instanceof Element && e.target.closest('.spot'); if (!card) return;
      const r = card.getBoundingClientRect();
      card.style.setProperty('--mx', `${e.clientX - r.left}px`); card.style.setProperty('--my', `${e.clientY - r.top}px`);
    });
    addEventListener('pointermove', spot, { passive: true });
  }

  // keyboard support for card-buttons
  document.addEventListener('keydown', (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches?.('[role="button"]')) { e.preventDefault(); e.target.click(); }
  });
  $('#bento-proof')?.addEventListener('click', () => $('#proof-fab')?.click());

  // ------------------------------------------------------------ hero hex field (canvas)
  (function hexField() {
    const c = $('#hex-field'); if (!c) return;
    const ctx = c.getContext('2d'); if (!ctx) return;
    const CH = '0123456789ABCDEF';
    let W = 0; let H = 0; let cell = 22; let cols = 0; let rows = 0; let grid; let heat; let colors = {};
    let mx = -1e4; let my = -1e4; let visible = true; let last = 0; let t0 = performance.now();
    const readColors = () => { const cs = getComputedStyle(html); colors = { base: cs.getPropertyValue('--muted').trim() || '#999', hot: cs.getPropertyValue('--accent-text').trim() || '#d4ff3a' }; };
    const resize = () => {
      const r = c.getBoundingClientRect(); if (!r.width) return;
      const dpr = Math.min(2, devicePixelRatio || 1);
      W = r.width; H = r.height; c.width = W * dpr; c.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      cell = W < 700 ? 19 : 23; cols = Math.ceil(W / cell); rows = Math.ceil(H / cell);
      grid = Uint8Array.from({ length: cols * rows }, () => (Math.random() * 16) | 0);
      heat = new Float32Array(cols * rows);
    };
    const draw = (now) => {
      if (!W) return;
      ctx.clearRect(0, 0, W, H);
      ctx.font = `500 ${Math.round(cell * 0.54)}px "JetBrains Mono", ui-monospace, monospace`;
      ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
      const n = cols * rows;
      for (let k = 0; k < n * 0.012; k++) grid[(Math.random() * n) | 0] = (Math.random() * 16) | 0;
      const wave = ((now - t0) * 0.00011 % 1.5 - 0.25) * (W + H * 0.6);
      const R = Math.min(200, W * 0.2);
      // pass 1: resting field
      ctx.fillStyle = colors.base;
      for (let j = 0; j < rows; j++) {
        for (let i = 0; i < cols; i++) {
          const idx = j * cols + i; const px = i * cell + cell / 2; const py = j * cell + cell / 2;
          const d = Math.hypot(px - mx, py - my);
          if (d < R) { const h = 1 - d / R; if (h > heat[idx]) heat[idx] = h; if (Math.random() < h * 0.25) grid[idx] = (Math.random() * 16) | 0; }
          if (heat[idx] > 0.04) continue;
          const wd = Math.abs(px + py * 0.6 - wave);
          ctx.globalAlpha = 0.07 + (wd < 140 ? (1 - wd / 140) * 0.22 : 0);
          ctx.fillText(CH[grid[idx]], px, py);
        }
      }
      // pass 2: cursor heat in the accent colour
      ctx.fillStyle = colors.hot;
      for (let idx = 0; idx < n; idx++) {
        const h = heat[idx]; if (h <= 0.04) continue;
        ctx.globalAlpha = 0.12 + h * 0.88;
        ctx.fillText(CH[grid[idx]], (idx % cols) * cell + cell / 2, ((idx / cols) | 0) * cell + cell / 2);
        heat[idx] = h * 0.93;
      }
      ctx.globalAlpha = 1;
    };
    const loop = (now) => {
      if (visible && !document.hidden && now - last > 33) { last = now; draw(now); }
      requestAnimationFrame(loop);
    };
    readColors(); resize();
    new MutationObserver(readColors).observe(html, { attributes: true, attributeFilter: ['data-theme'] });
    addEventListener('resize', raf(resize));
    if (window.ResizeObserver) new ResizeObserver(raf(resize)).observe(c);
    new IntersectionObserver((es) => { visible = es[0].isIntersecting; if (visible && !W) resize(); }).observe(c);
    addEventListener('pointermove', (e) => { const r = c.getBoundingClientRect(); mx = e.clientX - r.left; my = e.clientY - r.top; }, { passive: true });
    if (still) { draw(performance.now()); return; }
    requestAnimationFrame(loop);
  })();

  // ------------------------------------------------------------ hero "try it" (k-anonymity, live, nothing sent)
  (function tryCard() {
    const input = $('#hero-try'); const row = $('#try-hash'); if (!input || !row) return;
    const spans = [...row.children]; const HEX = '0123456789ABCDEF';
    let seq = 0; let nnTimer = null;
    const set = (id, text, cls = '') => { const el = $(`#${id}`); if (el) { el.textContent = text; el.className = cls; } };
    async function sha1(text) {
      const d = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
      return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }
    function paint(hex) {
      if (still) { spans.forEach((s, i) => { s.textContent = hex[i]; }); return; }
      const t0 = performance.now();
      const frame = (t) => {
        let pending = false;
        spans.forEach((s, i) => {
          if (t - t0 > i * 9 + 120) s.textContent = hex[i];
          else { s.textContent = HEX[(Math.random() * 16) | 0]; pending = true; }
        });
        if (pending) requestAnimationFrame(frame);
      };
      requestAnimationFrame(frame);
    }
    input.addEventListener('input', async () => {
      const v = input.value; const my = ++seq; clearTimeout(nnTimer);
      if (!v) { row.classList.remove('live'); spans.forEach((s) => { s.textContent = '0'; }); ['try-corpus', 'try-guess', 'try-crack'].forEach((id) => set(id, '—')); return; }
      const hex = await sha1(v.normalize('NFKC')); if (my !== seq) return;
      row.classList.add('live'); paint(hex);
      window.PrivPassBloom?.check(v).then((hit) => { if (my === seq) set('try-corpus', hit ? 'FOUND' : 'Not found', hit ? 'bad' : 'good'); })
        .catch(() => { if (my === seq) set('try-corpus', 'N/A'); });
      nnTimer = setTimeout(async () => {
        try {
          const nn = await (window.PrivPassGuess || window.PrivPassNeural)?.estimate(v); if (!nn || my !== seq) return;
          set('try-guess', `10^${nn.log10Guesses.toFixed(1)}`, nn.log10Guesses < 10 ? 'bad' : nn.log10Guesses < 14 ? 'warn' : 'good');
          set('try-crack', nn.crackTime || '—');
        } catch { set('try-guess', 'N/A'); }
      }, 160);
    });
    $('#try-full')?.addEventListener('click', () => {
      const v = input.value; const pw = $('#pw-input');
      if (v && pw) { pw.value = v; pw.type = 'text'; }
      window.nav?.('password');
      try { if (typeof resetBreachEvidence === 'function') resetBreachEvidence(); } catch { /* optional */ }
      try { if (typeof refreshPasswordAnalysis === 'function') refreshPasswordAnalysis(); } catch { /* optional */ }
      setTimeout(() => pw?.focus({ preventScroll: true }), 500);
    });
  })();

  // ------------------------------------------------------------ pinned scroll story
  const story = $('#story'); const visual = $('#story-visual'); const steps = $$('#story-steps li');
  const desktopStory = matchMedia('(min-width: 1081px)');
  function setStep(i) {
    if (!visual || visual.dataset.step === String(i)) return;
    visual.dataset.step = String(i);
    steps.forEach((li, k) => li.classList.toggle('active', k === i));
  }
  function storyScroll() {
    if (!story || !desktopStory.matches) return;
    const r = story.getBoundingClientRect(); if (!r.height) return;
    const p = clamp(-r.top / (r.height - innerHeight), 0, 0.999);
    setStep(Math.floor(p * steps.length));
  }
  if (steps.length && window.IntersectionObserver) {
    const sio = new IntersectionObserver((es) => {
      if (desktopStory.matches) return;
      es.forEach((e) => { if (e.isIntersecting) setStep(steps.indexOf(e.target)); });
    }, { rootMargin: '-45% 0px -45% 0px' });
    steps.forEach((li) => sio.observe(li));
  }

  // ------------------------------------------------------------ boot
  prepare(document);
  afterNav();
  addEventListener('resize', moveIndicator);
})();
