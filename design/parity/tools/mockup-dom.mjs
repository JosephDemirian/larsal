// Design parity (Verify): reads the Option A mockup's layout for the frames of
// the given sections, in headless Chrome offscreen (no window), and writes
// target/parity/dom-<theme>.json: every text run with its box, font and
// colour and whether it is visible inside its clipping parents; the main
// boxes; the Phosphor glyphs and brand logos; the clickable controls.
// Boxes are CSS points from the frame's top-left corner.
// Usage: node design/parity/tools/mockup-dom.mjs lock,main,states
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const { Browser } = await import(`${process.env.HOME}/.claude/skills/design-taste-frontend/scripts/lib/cdp.mjs`);
const root = join(dirname(fileURLToPath(import.meta.url)), '../../..');
const sections = (process.argv[2] || 'lock,main,states').split(',');
const out = join(root, 'target/parity');
mkdirSync(out, { recursive: true });

function extract() {
  const BOXES = {
    window: '.win', sidebar: '.sb', topbar: '.tb', sheet: '.sheet', rail: '.rail', search: '.search',
    vaultswitch: '.vsw', row: '.row', sideitem: '.si', tab: '.tab', menu: '.menu', menuitem: '.mi', tips: '.tips',
    tip: '.tips .ti', lock: '.lock', welcome: '.wel', dialog: '.dlg', empty: '.empty', button: '.btn',
    iconbutton: '.ibtn', field: '.fld', input: '.inp', toast: '.toast', month: '.month', lockfoot: '.lockfoot',
    list: '.rows', lights: '.lights', recent: '.rec', action: '.wel .act', touch: '.touch', card: '.ucard', link: 'a', meter: '.meter', tick: '.tick', codebar: '.bar', scrim: '.scrim',
  };
  const round = (v) => Math.round(v * 2) / 2;
  const box = (r, o) => [round(r.x - o.x), round(r.y - o.y), round(r.width), round(r.height)];
  const clip = (el, frameEl) => {
    // The visible part of el's box after every clipping parent up to the frame.
    let r = el.getBoundingClientRect();
    let x0 = r.left, y0 = r.top, x1 = r.right, y1 = r.bottom;
    for (let p = el.parentElement; p && p !== frameEl.parentElement; p = p.parentElement) {
      const cs = getComputedStyle(p);
      if (cs.overflowX !== 'visible' || cs.overflowY !== 'visible' || p === frameEl) {
        const q = p.getBoundingClientRect();
        x0 = Math.max(x0, q.left); y0 = Math.max(y0, q.top); x1 = Math.min(x1, q.right); y1 = Math.min(y1, q.bottom);
      }
    }
    return x1 - x0 > 1 && y1 - y0 > 1;
  };
  const shown = (el) => {
    for (let p = el; p; p = p.parentElement) {
      const cs = getComputedStyle(p);
      if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    }
    return true;
  };
  return [...document.querySelectorAll('.frame')].map((fig) => {
    const w = fig.querySelector('.win');
    const frameEl = w.classList.contains('cardwin') ? w.firstElementChild : w;
    const o = frameEl.getBoundingClientRect();
    const texts = [];
    const walker = document.createTreeWalker(w, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const text = n.textContent.replace(/\s+/g, ' ').trim();
      const el = n.parentElement;
      if (!text || el.closest('i.ph, i.ph-fill, svg, style, script')) continue;
      const range = document.createRange();
      range.selectNodeContents(n);
      const r = range.getBoundingClientRect();
      const cs = getComputedStyle(el);
      texts.push({
        text, box: box(r, o), visible: shown(el) && clip(el, frameEl) && r.width > 0,
        font: cs.fontFamily.split(',')[0].replace(/"/g, '').trim(), size: parseFloat(cs.fontSize), weight: +cs.fontWeight,
        color: cs.color, tag: el.tagName.toLowerCase(), cls: el.className && el.className.baseVal === undefined ? el.className : '',
      });
    }
    const boxes = [];
    for (const [kind, sel] of Object.entries(BOXES)) {
      for (const el of w.querySelectorAll(sel)) {
        const cs = getComputedStyle(el);
        boxes.push({
          kind, box: box(el.getBoundingClientRect(), o), visible: shown(el) && clip(el, frameEl),
          text: (el.innerText || el.getAttribute('aria-label') || '').replace(/\s+/g, ' ').trim().slice(0, 60),
          label: el.getAttribute('aria-label') || '',
          radius: cs.borderTopLeftRadius, background: cs.backgroundColor, border: cs.borderTopWidth + ' ' + cs.borderTopColor,
        });
      }
    }
    if (frameEl.matches('.win')) boxes.unshift({ kind: 'window', box: [0, 0, Math.round(o.width), Math.round(o.height)], visible: true, text: '', radius: getComputedStyle(frameEl).borderTopLeftRadius });
    const icons = [...w.querySelectorAll('i.ph, i.ph-fill')].map((el) => ({
      name: [...el.classList].find((c) => c.startsWith('ph-') && c !== 'ph-fill'), fill: el.classList.contains('ph-fill'),
      size: parseFloat(getComputedStyle(el).fontSize), box: box(el.getBoundingClientRect(), o), visible: shown(el) && clip(el, frameEl),
    }));
    const names = [...w.querySelectorAll('[aria-label]')].map((el) => ({ label: el.getAttribute('aria-label'), visible: shown(el) && clip(el, frameEl) }));
    const logos = [...w.querySelectorAll('.logo')].map((el) => ({
      label: el.getAttribute('aria-label') || el.querySelector('[aria-label]')?.getAttribute('aria-label') || '', brand: !!el.querySelector('svg'), letter: el.classList.contains('letter') ? el.textContent.trim() : '',
      box: box(el.getBoundingClientRect(), o), visible: shown(el) && clip(el, frameEl),
    }));
    const controls = [...w.querySelectorAll('[data-a], button, a, input, [tabindex], [role=button], [role=tab], [role=switch], [role=checkbox]')].map((el) => ({
      action: el.dataset.a || '', value: el.dataset.v || '', tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || '',
      label: (el.getAttribute('aria-label') || el.innerText || el.getAttribute('placeholder') || '').replace(/\s+/g, ' ').trim().slice(0, 60),
      disabled: el.disabled || el.getAttribute('aria-disabled') === 'true', box: box(el.getBoundingClientRect(), o), visible: shown(el) && clip(el, frameEl),
    }));
    return { id: fig.id, size: [Math.round(o.width), Math.round(o.height)], texts, boxes, icons, logos, names, controls };
  });
}

const browser = await Browser.launch({ width: 1500, height: 1000 });
try {
  for (const theme of ['light', 'dark']) {
    const page = await browser.newPage({ width: 1500, height: 1000, dsf: 1 });
    const url = `file://${join(root, 'design/option-a/mockup.html')}?theme=${theme}&zoom=1&t=1793088610000&only=${sections.join(',')}`;
    await page.goto(url, { settleMs: 2000 });
    const frames = await page.eval(extract);
    writeFileSync(join(out, `dom-${theme}.json`), JSON.stringify(frames));
    console.log(`${theme}: ${frames.length} frames, ${frames.reduce((n, f) => n + f.texts.length, 0)} text runs -> target/parity/dom-${theme}.json`);
    await page.close();
  }
} finally {
  await browser.close();
}
