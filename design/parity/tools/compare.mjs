// Design parity (Verify): compares one section of design/option-a/mockup.html
// with the app's offscreen snapshots, frame by frame, light and dark.
// Inputs: manifest.json, reference/<theme>/<id>.png, target/parity/dom-<theme>.json
// (mockup-dom.mjs), target/larsal-shots/<theme>/<id>.png and .ax.json (SnapshotTests),
// target/parity/ocr/<theme>/<id>.json (ocr.swift), target/parity/behaviour.log
// (xcodebuild output of ParityTests) and the lead's decisions in notes.mjs.
// Writes design/parity/<section>/: findings.json, report.md, report.html,
// app/<theme>/<id>.png (the snapshot checked) and diff/<theme>/<id>.png.
// Pixel diff: pixelmatch, threshold 0.1, anti-aliasing ignored. The check
// tools live outside the project: PARITY_TOOLS (default
// /tmp/parity-tools/node_modules, `npm install --prefix /tmp/parity-tools pixelmatch pngjs`).
// Usage: node design/parity/tools/compare.mjs <section>
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const tools = process.env.PARITY_TOOLS || '/tmp/parity-tools/node_modules';
const { default: pixelmatch } = await import(join(tools, 'pixelmatch/index.js'));
const { PNG } = createRequire(import.meta.url)(join(tools, 'pngjs'));
const versions = ['pixelmatch', 'pngjs'].map((n) => `${n} ${JSON.parse(readFileSync(join(tools, n, 'package.json'))).version}`);
const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../../..');
const { NOTES, RULES, LATER, COMMANDS } = await import(join(here, 'notes.mjs'));
const { pixelText } = await import(join(here, 'pixels.mjs'));
const section = process.argv[2];
const out = join(root, 'design/parity', section);
const read = (p) => readFileSync(join(root, p), 'utf8');
const json = (p) => JSON.parse(read(p));
const manifest = json('design/option-a/manifest.json').list.filter((f) => f.section === section);
const THEMES = ['light', 'dark'];
const dom = Object.fromEntries(THEMES.map((t) => [t, Object.fromEntries(json(`target/parity/dom-${t}.json`).map((f) => [f.id, f]))]));

// ---------- text helpers ----------
const norm = (s) => String(s).replace(/[   ]/g, ' ').replace(/\s+/g, ' ').trim();
const loose = (s) => norm(s).replace(/[•·]/g, '·').replace(/\.\.\./g, '…').toLowerCase();
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const FIELDS = ['label', 'title', 'value', 'placeholder', 'help'];

function flat(tree) {
  const nodes = [];
  (function walk(n) { nodes.push(n); for (const c of n.children || []) walk(c); })(tree);
  return nodes;
}
function axStrings(nodes) {
  const all = [];
  for (const n of nodes) for (const k of FIELDS) if (n[k]) all.push({ text: norm(n[k]), field: k, node: n, parts: k === 'label' || k === 'title' ? norm(n[k]).split(', ').map(norm) : [norm(n[k])] });
  // Texts that SwiftUI splits into runs on one line ("Other vaults: ", "Work ") read as one line.
  for (const n of nodes) {
    const runs = (n.children || []).filter((c) => c.role === 'AXStaticText' && c.value).sort((a, b) => a.frame[1] - b.frame[1] || a.frame[0] - b.frame[0]);
    for (let i = 0; i < runs.length; i++) {
      let line = runs[i].value, last = runs[i];
      for (let j = i + 1; j < runs.length && Math.abs(runs[j].frame[1] - runs[i].frame[1]) <= 2 && runs[j].frame[0] - (last.frame[0] + last.frame[2]) <= 20; j++) {
        line += runs[j].value; last = runs[j];
        all.push({ text: norm(line), field: 'line', node: runs[i], parts: [norm(line)] });
      }
    }
  }
  return all;
}
function findAx(m, strings) {
  for (const s of strings) if (s.text === m) return { how: 'exact', s };
  for (const s of strings) if (s.parts.includes(m)) return { how: 'part', s };
  if (m.length >= 3) for (const s of strings) if (s.text.includes(m)) return { how: 'inside', s };
  return null;
}
function findOcr(m, ocr) {
  const l = loose(m);
  return ocr.find((o) => (l.length <= 2 ? loose(o.text) === l || loose(o.text).split(' ').includes(l) : loose(o.text).includes(l)));
}

// ---------- tokens ----------
const css = read('design/option-a/app.css');
const block = (sel) => {
  const m = css.match(new RegExp(sel.replace(/\./g, '\\.') + '\\s*\\{([^}]*)\\}'));
  return Object.fromEntries([...m[1].matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6}|rgba?\([^)]*\))/gi)].map((x) => [x[1], x[2].toLowerCase()]));
};
const TOK = { light: block('.win.light'), dark: block('.win.dark'), root: block(':root') };
const hexRgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
const rgbHex = (c) => '#' + c.map((v) => v.toString(16).padStart(2, '0')).join('');
function tokenOf(rgb, theme) {
  const hits = [];
  for (const set of [TOK[theme], TOK.root]) for (const [k, v] of Object.entries(set)) if (v.startsWith('#') && dist(hexRgb(v), rgb) <= 3) hits.push(k);
  return [...new Set(hits)].join('/');
}
const dist = (a, b) => Math.abs(a[0] - b[0]) + Math.abs(a[1] - b[1]) + Math.abs(a[2] - b[2]);
function colorsets() {
  const base = 'macos/Larsal/Resources/Assets.xcassets/Colors';
  const rows = [];
  for (const name of Object.keys({ ...TOK.light, ...TOK.root })) {
    const p = `${base}/${name}.colorset/Contents.json`;
    if (!existsSync(join(root, p))) { if (TOK.light[name]?.startsWith('#')) rows.push({ name, light: TOK.light[name], dark: TOK.dark[name], app: 'missing', ok: false }); continue; }
    const c = json(p).colors;
    const get = (dark) => {
      const e = c.find((x) => (x.appearances || []).some((a) => a.value === 'dark') === dark) || c[0];
      const k = e.color.components;
      return { rgb: ['red', 'green', 'blue'].map((x) => Math.round(parseFloat(k[x]) * 255)), a: parseFloat(k.alpha) };
    };
    const want = (t) => (TOK[t][name] ?? TOK.root[name]);
    const res = { name };
    let ok = true;
    for (const t of THEMES) {
      const w = want(t), g = get(t === 'dark');
      res[t] = w;
      res[`app_${t}`] = rgbHex(g.rgb) + (g.a < 1 ? ` α${g.a}` : '');
      if (w.startsWith('#')) ok &&= dist(hexRgb(w), g.rgb) <= 1 && g.a === 1;
      else { const m = w.match(/rgba?\(([^)]*)\)/)[1].split(',').map((x) => parseFloat(x)); ok &&= dist(m.slice(0, 3), g.rgb) <= 1 && Math.abs((m[3] ?? 1) - g.a) < 0.01; }
    }
    res.ok = ok;
    rows.push(res);
  }
  return rows;
}

// WCAG contrast of the token pairs that carry words.
const lum = (hex) => { const c = hexRgb(hex).map((v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; }); return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]; };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const PAIRS = [['text', 'ground'], ['text', 'surface'], ['text', 'raised'], ['text', 'active'], ['muted', 'ground'], ['muted', 'surface'], ['muted', 'raised'], ['muted', 'active'], ['muted', 'field'],
  ['accent', 'surface'], ['accent', 'accent-soft'], ['negative', 'surface'], ['positive', 'surface'], ['warning', 'surface'], ['neg-ink', 'neg-bg'], ['warn-ink', 'warn-bg'], ['pos-ink', 'pos-bg'],
  ['chip-ink', 'chip-bg'], ['on-primary', 'primary'], ['digit', 'surface'], ['symbol', 'surface']];
const contrast = THEMES.flatMap((t) => PAIRS.map(([f, b]) => ({ theme: t, pair: `${f} on ${b}`, ratio: +ratio(TOK[t][f], TOK[t][b]).toFixed(2) })));

// ---------- images ----------
const png = (p) => PNG.sync.read(readFileSync(p));
function histogram(img, boxes = []) {
  const counts = new Map();
  const d = img.data;
  // Pixels inside accepted boxes (points; the PNGs are 2x) are left out.
  const inBox = (x, y) => boxes.some(([bx, by, bw, bh]) => x >= bx * 2 && x < (bx + bw) * 2 && y >= by * 2 && y < (by + bh) * 2);
  let total = 0;
  for (let i = 0; i < d.length; i += 4) {
    const p = i / 4;
    if (boxes.length && inBox(p % img.width, Math.floor(p / img.width))) continue;
    const k = (d[i] << 16) | (d[i + 1] << 8) | d[i + 2];
    counts.set(k, (counts.get(k) || 0) + 1);
    total++;
  }
  return [...counts].map(([k, n]) => ({ rgb: [k >> 16, (k >> 8) & 255, k & 255], share: (n / total) * 100 })).sort((a, b) => b.share - a.share);
}
function colourCheck(ref, app, theme, boxes = []) {
  const hr = histogram(ref, boxes), ha = histogram(app, boxes);
  const near = (h, rgb) => h.filter((c) => dist(c.rgb, rgb) <= 6).reduce((s, c) => s + c.share, 0);
  const issues = [];
  for (const c of hr.filter((c) => c.share >= 0.5)) {
    const a = near(ha, c.rgb), r = near(hr, c.rgb);
    if (a < r * 0.25 && r - a > 0.5) issues.push({ kind: 'missing', hex: rgbHex(c.rgb), token: tokenOf(c.rgb, theme), ref: +r.toFixed(2), app: +a.toFixed(2) });
  }
  for (const c of ha.filter((c) => c.share >= 0.5)) {
    const a = near(ha, c.rgb), r = near(hr, c.rgb);
    if (r < a * 0.25 && a - r > 0.5) issues.push({ kind: 'extra', hex: rgbHex(c.rgb), token: tokenOf(c.rgb, theme), ref: +r.toFixed(2), app: +a.toFixed(2) });
  }
  const major = hr.filter((c) => c.share >= 2).map((c) => ({ hex: rgbHex(c.rgb), token: tokenOf(c.rgb, theme), ref: +c.share.toFixed(1), app: +near(ha, c.rgb).toFixed(1) }));
  return { issues, major };
}
// The sheet's edges, read from pixels: where the ground meets the sheet.
function sheetEdges(img, theme, sidebar) {
  const ground = hexRgb(TOK[theme].ground);
  const at = (x, y) => { const i = (img.width * Math.round(y * 2) + Math.round(x * 2)) * 4; return [img.data[i], img.data[i + 1], img.data[i + 2]]; };
  const W = img.width / 2, H = img.height / 2;
  const isGround = (x, y) => dist(at(x, y), ground) <= 6;
  const scan = (from, to, step, f) => { for (let v = from; step > 0 ? v <= to : v >= to; v += step) if (!f(v)) return v; return null; };
  // Lines clear of the top bar's search, the vault switcher and open menus.
  const y = H - 14, x = 700;
  return {
    left: scan(sidebar ? 240 : 0, 400, 0.5, (v) => isGround(v, y)), right: scan(W - 0.5, W - 60, -0.5, (v) => isGround(v, y)),
    top: scan(44, 120, 0.5, (v) => isGround(x, v)), bottom: scan(H - 0.5, H - 60, -0.5, (v) => isGround(x, v)),
  };
}
function maskCount(diff, boxes) {
  const { width: w, height: h, data } = diff;
  const mask = new Uint8Array(w * h);
  for (const [x, y, bw, bh] of boxes) {
    for (let yy = Math.max(0, Math.floor((y - 2) * 2)); yy < Math.min(h, Math.ceil((y + bh + 2) * 2)); yy++)
      for (let xx = Math.max(0, Math.floor((x - 2) * 2)); xx < Math.min(w, Math.ceil((x + bw + 2) * 2)); xx++) mask[yy * w + xx] = 1;
  }
  let n = 0;
  for (let i = 0; i < w * h; i++) if (!mask[i] && data[i * 4] === 255 && data[i * 4 + 1] === 0 && data[i * 4 + 2] === 0) n++;
  return (n / (w * h)) * 100;
}

// ---------- geometry ----------
const ANCHORED = ['sideitem', 'row', 'tab', 'menuitem', 'tip', 'button', 'iconbutton', 'vaultswitch', 'recent', 'action', 'touch', 'link'];
const CONTAINERS = ['sidebar', 'rail', 'list', 'menu', 'tips', 'lock', 'welcome', 'dialog', 'empty'];
const INTERACTIVE = new Set(['AXButton', 'AXMenuItem', 'AXRadioButton', 'AXCheckBox', 'AXPopUpButton', 'AXLink', 'AXTextField', 'AXRow', 'AXCell', 'AXTab']);
const iou = (a, b) => {
  const x0 = Math.max(a[0], b[0]), y0 = Math.max(a[1], b[1]), x1 = Math.min(a[0] + a[2], b[0] + b[2]), y1 = Math.min(a[1] + a[3], b[1] + b[3]);
  const i = Math.max(0, x1 - x0) * Math.max(0, y1 - y0);
  return i / (a[2] * a[3] + b[2] * b[3] - i || 1);
};
const delta = (d, a) => [0, 1, 2, 3].map((i) => +(a[i] - d[i]).toFixed(1));
const worst = (dl) => Math.max(...dl.map(Math.abs));
function geometry(f, nodes) {
  const res = [];
  for (const b of f.boxes.filter((b) => b.visible && ANCHORED.includes(b.kind))) {
    const key = norm(b.text), aria = norm(b.label || '');
    if (!key && !aria) continue;
    const cands = nodes.filter((n) => INTERACTIVE.has(n.role)).filter((n) => {
      const p = norm(n.label || n.title || n.value || '').split(', ')[0], v = norm(n.value || '');
      return (p && (key === p || key.startsWith(p + ' ') || (key && p.startsWith(key)) || aria === p)) || (v && key === v);
    });
    if (!cands.length) {
      // A control whose words the lead accepted as different: find it by the app's words.
      const rule = RULES.find((x) => x.test(key) || (aria && x.test(aria)));
      const pat = rule?.app && (typeof rule.app === 'function' ? rule.app(rule.test(key) ? key : aria) : rule.app);
      if (pat) cands.push(...nodes.filter((n) => INTERACTIVE.has(n.role) && ['label', 'title', 'value', 'help'].some((k) => n[k] && pat.test(norm(n[k]).split(', ')[0]))));
    }
    if (!cands.length) { res.push({ kind: b.kind, text: key, dom: b.box, app: null }); continue; }
    const best = cands.sort((m, n) => Math.hypot(m.frame[0] - b.box[0], m.frame[1] - b.box[1]) - Math.hypot(n.frame[0] - b.box[0], n.frame[1] - b.box[1]))[0];
    const app = best.frame.map((v) => +v.toFixed(1));
    res.push({ kind: b.kind, text: key, dom: b.box, app, d: delta(b.box, app) });
  }
  for (const b of f.boxes.filter((b) => b.visible && CONTAINERS.includes(b.kind))) {
    const best = nodes.slice(1).map((n) => ({ n, s: iou(b.box, n.frame) })).sort((p, q) => q.s - p.s)[0];
    if (best && best.s >= 0.3) res.push({ kind: b.kind, text: norm(b.text).slice(0, 30), dom: b.box, app: best.n.frame.map((v) => +v.toFixed(1)), d: delta(b.box, best.n.frame) });
    else res.push({ kind: b.kind, text: norm(b.text).slice(0, 30), dom: b.box, app: null, note: 'no accessibility element; see pixels' });
  }
  return res;
}
function textRuns(f, nodes) {
  const texts = nodes.filter((n) => ['AXStaticText', 'AXHeading'].includes(n.role));
  const res = [];
  for (const t of f.texts.filter((t) => t.visible)) {
    const c = texts.filter((n) => norm(n.value || n.label || '') === t.text);
    if (!c.length) continue;
    const best = c.sort((m, n) => Math.hypot(m.frame[0] - t.box[0], m.frame[1] - t.box[1]) - Math.hypot(n.frame[0] - t.box[0], n.frame[1] - t.box[1]))[0];
    // The same words elsewhere on screen are another text, not this one moved.
    if (Math.hypot(best.frame[0] - t.box[0], best.frame[1] - t.box[1]) > 60) continue;
    res.push({ text: t.text, font: `${t.font} ${t.size}/${t.weight}`, dom: t.box, app: best.frame.map((v) => +v.toFixed(1)), d: delta(t.box, best.frame) });
  }
  return res;
}

// ---------- icons and logos ----------
const glyphs = new Set([...read('macos/Larsal/Glyphs.swift').matchAll(/"([a-z0-9-]+)": 0x/g)].map((m) => m[1]));
const swift = ['Controls', 'DetailFields', 'EntryListView', 'MainWindow', 'Menus', 'PopMenu', 'RailView', 'SidebarView', 'Theme', 'UnlockView', 'VaultView', 'WelcomeView', 'Logos', 'Formats', 'VaultModel', 'EditorModel', 'EditorScreen', 'EditorEntryPage', 'EditorPages', 'EditorMorePages', 'Dialogs', 'DialogSheets', 'Forms', 'FormParts', 'Generator', 'GeneratorPanel', 'NewVaultView', 'VaultSettingsView', 'LarsalSettingsView', 'LarsalSettingsPages', 'LarsalSettingsMorePages', 'LarsalSettingsParts', 'MenuBarIcon'].map((n) => read(`macos/Larsal/${n}.swift`)).join('\n');
const brands = new Set([...read('macos/Larsal/Logos.swift').matchAll(/"brand-([a-z0-9]+)"/g)].map((m) => m[1]).concat(
  ['apple', 'github', 'google', 'hetzner', 'protonmail', 'paypal', 'instagram', 'wise', 'figma', 'mastodon', 'linear', 'zalando', 'deutschebahn', 'ebay', 'netflix', 'reddit', 'visa', 'x', 'jira', 'yubico', 'postgresql'].filter((b) => existsSync(join(root, `macos/Larsal/Resources/Assets.xcassets/Brands/brand-${b}.imageset`)))));
function iconCheck(f) {
  const used = [...new Set(f.icons.filter((i) => i.visible).map((i) => `${i.fill ? 'fill ' : ''}${i.name.slice(3)}`))];
  const missing = used.filter((u) => { const n = u.replace(/^fill /, ''); return !glyphs.has(n) || !swift.includes(`"${n}"`); });
  const logos = f.logos.filter((l) => l.visible && l.brand).map((l) => l.label);
  const noLogo = logos.filter((l) => !brands.has(l.toLowerCase().replace(/[^a-z0-9]/g, '')));
  return { used, missing, logos, noLogo };
}

// ---------- behaviour ----------
const blog = existsSync(join(root, 'target/parity/behaviour.log')) ? read('target/parity/behaviour.log') : '';
// Looks measured by ParityFontTests (LD-169): the code font and the focused row.
const measured = (name) => { const m = blog.match(new RegExp(`([✔✘]) Test "${name}[^"]*" (passed|failed|recorded)`)); return m ? m[1] === '✔' && m[2] === 'passed' : null; };
const FONT_OK = measured('Font check'), FOCUS_OK = measured('Focus check');
const fontLines = [...blog.matchAll(/Font check (\d{3}.\d{3}) at ([\d.]+) pt: ink distance ([\d.]+) to IBM Plex Mono 500, ([\d.]+) to the system face/g)].map((m) => `${m[2]} pt code: ink distance ${(+m[3]).toFixed(3)} to IBM Plex Mono 500 against ${(+m[4]).toFixed(3)} to the system face`);
function behaviour(id) {
  const rows = [];
  for (const m of blog.matchAll(/([✔✘]) Test "Parity ([a-z0-9-]+): ([^"]+)" (passed|failed|recorded)[^\n]*/g)) if (m[2] === id) rows.push({ ok: m[1] === '✔' && m[4] === 'passed', name: m[3] });
  return rows;
}

// ---------- per frame ----------
mkdirSync(out, { recursive: true });
const tokensStatic = colorsets();
const results = [];
for (const f of manifest) {
  const later = LATER[f.id];
  const r = { id: f.id, title: f.title, note: f.note, size: [f.width, f.height], later, themes: {} };
  for (const theme of THEMES) {
    const t = { theme };
    r.themes[theme] = t;
    const refPath = join(root, `design/option-a/reference/${theme}/${f.id}.png`);
    const appPath = join(root, `target/larsal-shots/${theme}/${f.id}.png`);
    t.refImg = relative(out, refPath);
    t.present = existsSync(appPath);
    if (!t.present) continue;
    const appCopy = join(out, `app/${theme}/${f.id}.png`), diffPath = join(out, `diff/${theme}/${f.id}.png`);
    mkdirSync(dirname(appCopy), { recursive: true }); mkdirSync(dirname(diffPath), { recursive: true });
    copyFileSync(appPath, appCopy);
    t.appImg = relative(out, appCopy); t.diffImg = relative(out, diffPath);
    const d = dom[theme][f.id];
    const nodes = flat(JSON.parse(readFileSync(appPath.replace(/\.png$/, '.ax.json'), 'utf8')));
    const strings = axStrings(nodes);
    // The view behind an open modal menu, from the same view without the menu.
    const behindNodes = (NOTES[f.id]?.behind || []).flatMap((id) => flat(JSON.parse(readFileSync(join(root, `target/larsal-shots/${theme}/${id}.ax.json`), 'utf8'))));
    const behindStrings = axStrings(behindNodes);
    const ocrPath = join(root, `target/parity/ocr/${theme}/${f.id}.json`);
    const ocr = existsSync(ocrPath) ? JSON.parse(readFileSync(ocrPath, 'utf8')) : [];
    // 2. Text
    const visible = (m) => d.texts.some((x) => x.visible && (x.text === m || (m.length > 2 && (x.text.includes(m) || (m.includes(x.text) && x.text.length > 3)))));
    const nameVisible = (m) => !d.names.some((x) => x.label === m) || d.names.some((x) => x.label === m && x.visible);
    const rules = RULES.filter((x) => !x.frames || x.frames.includes(f.id));
    const text = { found: [], accepted: [], live: [], clipped: [], drawnOnly: [], behind: [], missing: [] };
    // Areas the lead accepted as different (a live QR symbol, LD-192 (4)).
    const masks = [...(NOTES[f.id]?.mask || [])];
    // Masks cover exactly the accepted string, never a single character.
    const domBoxes = (m) => (m.length > 1 ? d.texts.filter((x) => x.text === m).map((x) => x.box) : []);
    // An accepted rule holds only when the app shows the value it names:
    // every pattern (`all`, e.g. both buttons of a row) found on screen.
    const ruleHits = (rule, m) => {
      const pats = rule.all || [typeof rule.app === 'function' ? rule.app(m) : rule.app];
      const hits = pats.map((pat) => {
        const hitIn = (list) => list.find((s) => s.parts.some((p) => pat.test(p)) || pat.test(s.text));
        const h = hitIn(strings) || ocr.find((o) => pat.test(norm(o.text))) || hitIn(behindStrings);
        return h && { h, part: h.parts?.find((x) => pat.test(x)) || norm(h.text) };
      });
      return hits.every(Boolean) ? hits : null;
    };
    for (const [list, kind] of [[f.texts, 'text'], [f.accessibleNames, 'name'], [f.placeholders, 'placeholder']]) {
      for (const raw of list) {
        const m = norm(raw);
        const hit = kind === 'placeholder' ? strings.find((s) => s.field === 'placeholder' && s.text === m) && { how: 'exact' } : findAx(m, strings);
        if (hit) { text.found.push({ m, kind, how: hit.how }); continue; }
        // A table row (the mockup's innerText joins its cells with tabs):
        // each cell is checked on its own, found or under an accepted rule.
        if (kind === 'text' && raw.includes('\t')) {
          const cells = raw.split('\t').map(norm).filter(Boolean);
          const cellOk = (c) => findAx(c, strings) || findOcr(c, ocr) || rules.some((x) => x.test(c, kind) && ruleHits(x, c));
          if (cells.every(cellOk)) { text.found.push({ m, kind, how: 'cells' }); continue; }
        }
        const rule = rules.find((x) => x.test(m, kind));
        const hits = rule && ruleHits(rule, m);
        if (hits) {
          const entry = { m, kind, why: rule.why, ref: rule.ref, app: hits.map((x) => x.part).join(' + ') };
          (rule.live ? text.live : text.accepted).push(entry);
          masks.push(...domBoxes(m));
          for (const { h, part } of hits) {
            if (part.length < 2) continue;
            if (h.node) masks.push(h.node.frame); else if (h.box) masks.push(h.box);
          }
          continue;
        }
        if ((kind === 'text' && !visible(m)) || (kind === 'name' && !nameVisible(m))) { text.clipped.push({ m, kind }); continue; }
        if (findAx(m, behindStrings)) { text.behind.push({ m, kind, frame: NOTES[f.id].behind.join(', ') }); continue; }
        const o = findOcr(m, ocr);
        if (o) { text.drawnOnly.push({ m, kind, ocr: o.text }); continue; }
        const proof = NOTES[f.id]?.drawn?.[m];
        if (proof && existsSync(join(out, proof.replace('<theme>', theme)))) { text.drawnOnly.push({ m, kind, ocr: `seen in ${proof.replace('<theme>', theme)}` }); continue; }
        text.missing.push({ m, kind });
      }
    }
    const known = new Set([...f.texts, ...f.accessibleNames, ...f.placeholders].map(norm));
    // Joined runs ('line') are a reading aid, not strings: their joins can
    // spell words no element holds, so only real strings count as extra.
    text.extra = [...new Set(strings.filter((s) => s.field !== 'help' && s.field !== 'line').flatMap((s) => s.parts).filter((p) => p && !known.has(p) && ![...known].some((k) => k.length >= 3 && (p.includes(k) || k.includes(p))) && !RULES.some((x) => x.app && typeof x.app !== 'function' && x.app.test(p))))];
    text.help = [...new Set(strings.filter((s) => s.field === 'help').map((s) => s.text))];
    t.text = text;
    for (const b of d.boxes.filter((b) => ['lights', 'meter', 'tick', 'codebar'].includes(b.kind) && b.visible)) masks.push(b.box);
    // 3. Tokens
    const ref = png(refPath), app = png(appPath);
    t.sizeOk = ref.width === app.width && ref.height === app.height;
    t.sizes = { ref: [ref.width, ref.height], app: [app.width, app.height] };
    const look = NOTES[f.id]?.fixedTheme || theme;
    // An accepted area (a live QR panel) is left out of the colour shares too.
    t.colours = t.sizeOk ? colourCheck(ref, app, look, NOTES[f.id]?.mask || []) : null;
    t.icons = iconCheck(d);
    // 4. Geometry
    // With a modal menu open only the menu is in the tree: compare what lies in it.
    const menus = d.boxes.filter((b) => b.visible && ['menu', 'tips'].includes(b.kind)).map((b) => b.box);
    const inMenu = (box) => menus.some((m) => box[0] >= m[0] - 1 && box[1] >= m[1] - 1 && box[0] + box[2] <= m[0] + m[2] + 1 && box[1] + box[3] <= m[1] + m[3] + 1);
    const scope = NOTES[f.id]?.behind ? { ...d, boxes: d.boxes.filter((b) => ['menu', 'tips'].includes(b.kind) || inMenu(b.box)), texts: d.texts.filter((x) => inMenu(x.box)) } : d;
    t.geometry = geometry(scope, nodes);
    t.runs = textRuns(scope, nodes);
    const side = d.boxes.some((b) => b.kind === 'sidebar' && b.visible);
    if (d.boxes.some((b) => b.kind === 'sheet' && b.visible)) t.sheet = { ref: sheetEdges(ref, look, side), app: sheetEdges(app, look, side) };
    // 5. Pixels
    if (t.sizeOk) {
      const diff = new PNG({ width: ref.width, height: ref.height });
      const n = pixelmatch(ref.data, app.data, diff.data, ref.width, ref.height, { threshold: 0.1, includeAA: false });
      writeFileSync(diffPath, PNG.sync.write(diff));
      t.pixels = +((n / (ref.width * ref.height)) * 100).toFixed(2);
      t.residual = +maskCount(diff, masks).toFixed(2);
    }
    // 7. Accessibility: interactive elements without a name.
    t.unnamed = nodes.filter((n) => INTERACTIVE.has(n.role) && !n.label && !n.title && !(n.role === 'AXTextField' && n.placeholder)).map((n) => `${n.role} at ${n.frame.map(Math.round).join(',')}`);
    t.disabled = nodes.filter((n) => INTERACTIVE.has(n.role) && n.disabled).map((n) => `${n.label || n.title}${n.help ? ' (' + n.help + ')' : ''}`);
  }
  r.behaviour = behaviour(NOTES[f.id]?.behaviourFrom || f.id);
  r.controls = (dom.light[f.id]?.controls || []).filter((c) => c.visible && c.action).map((c) => `${c.action}${c.value ? '=' + c.value : ''} "${c.label}"`);
  results.push(r);
}

// ---------- verdicts ----------
const GEO_KINDS = new Set([...ANCHORED, ...CONTAINERS]);
for (const r of results) {
  const note = NOTES[r.id] || {};
  if (r.later) { r.verdict = `later story (${r.later})`; continue; }
  const fails = [];
  for (const theme of THEMES) {
    const t = r.themes[theme];
    if (!t.present) { fails.push(`${theme}: frame missing`); continue; }
    if (t.text.missing.length) fails.push(`${theme}: ${t.text.missing.length} missing string(s)`);
    const skip = (g) => (note.geoSkip || []).some((x) => `${g.kind}:${g.text}`.startsWith(x));
    // A recorded shift (LD-169): boxes in the area move by exactly dy; judge what is left.
    const shift = (g) => (note.geoShift || []).find((z) => g.dom[0] >= z.x0 && g.dom[1] >= z.y0 && g.dom[1] < (z.y1 ?? 1e9));
    const rest = (g) => { const z = shift(g); return z ? [g.d[0], +(g.d[1] - z.dy).toFixed(1), ...g.d.slice(2)] : g.d; };
    t.shifted = t.geometry.filter((g) => g.d && shift(g)).map((g) => ({ kind: g.kind, text: g.text, d: g.d, rest: rest(g), ref: shift(g).ref }));
    const geo = t.geometry.filter((g) => g.d && GEO_KINDS.has(g.kind) && worst(rest(g)) > 2 && !skip(g));
    t.geoFails = geo.length;
    if (geo.length) fails.push(`${theme}: ${geo.length} box(es) off by more than 2 pt (${geo.slice(0, 4).map((g) => `${g.kind} "${g.text.slice(0, 24)}" Δ ${g.d.join(',')}`).join('; ')}${geo.length > 4 ? '; …' : ''})`);
    const runRest = (x) => { const z = shift({ dom: x.dom }); return z ? [x.d[0], x.d[1] - z.dy] : x.d; };
    t.shiftedRuns = t.runs.filter((x) => shift({ dom: x.dom })).map((x) => ({ text: x.text, d: x.d, rest: runRest(x).map((v) => +v.toFixed(1)) }));
    const runSkip = (x) => (note.runSkip || []).some((p) => x.text.startsWith(p));
    const moved = t.runs.filter((x) => !runSkip(x) && Math.max(Math.abs(runRest(x)[0]), Math.abs(runRest(x)[1])) > 2);
    t.runFails = moved.length;
    if (moved.length) fails.push(`${theme}: ${moved.length} of ${t.runs.length} text runs placed more than 2 pt off (${moved.slice(0, 4).map((x) => `"${x.text.slice(0, 24)}" Δ ${x.d[0]},${x.d[1]}`).join('; ')}${moved.length > 4 ? '; …' : ''})`);
    if (t.sheet) { const s = ['left', 'right', 'top', 'bottom'].filter((k) => Math.abs((t.sheet.app[k] ?? 0) - (t.sheet.ref[k] ?? 0)) > 2); if (s.length) fails.push(`${theme}: sheet edge ${s.join(', ')} off`); }
    if (t.pixels > 3 && t.residual > 3) fails.push(`${theme}: ${t.pixels} % pixels (${t.residual} % outside accepted areas)`);
    if (t.icons.missing.length) fails.push(`${theme}: glyph(s) not drawn by the app: ${t.icons.missing.join(', ')}`);
    if (t.unnamed.length) fails.push(`${theme}: ${t.unnamed.length} control(s) without a name`);
    if ((t.colours?.issues || []).filter((c) => !(note.colourOk || []).includes(c.hex)).length) fails.push(`${theme}: colour share differs (${t.colours.issues.map((c) => c.hex).join(', ')})`);
  }
  const lt = dom.light[r.id];
  r.hasCodes = lt.texts.some((t) => t.visible && t.font === 'IBM Plex Mono' && /^\d{3}[ \u2009]\d{3}$/.test(t.text));
  r.hasList = lt.boxes.some((b) => b.visible && b.kind === 'row');
  if (r.hasCodes && FONT_OK !== true) fails.push('tokens: one-time codes not measured as IBM Plex Mono 500 (Font check)');
  if (r.hasList && FOCUS_OK !== true) fails.push('accessibility: focused-row outline not measured (Focus check)');
  r.measured = [...(r.hasCodes ? [`Font check ${FONT_OK ? 'passed' : 'FAILED'}: the large code is one run of IBMPlexMono-Medium 28 in the accessibility tree; ${fontLines.join('; ')}.`] : []),
    ...(r.hasList ? [`Focus check ${FOCUS_OK ? 'passed' : 'FAILED'}: the focused row, rendered offscreen in light and dark, has --accent exactly from 1 to 3 pt outside its edge (left and top), none when not focused; the mockup's .win :focus-visible is outline 2px --accent, offset 1px, radius 6 (outline radius 7 to 9), the app strokes radius 8 at 2 pt out (7 to 9). On a real key window: Mac QA (LD-169).`] : [])];
  if (r.behaviour.some((b) => !b.ok)) fails.push('behaviour test failed');
  if (!r.behaviour.length) fails.push('no behaviour test');
  for (const x of note.fails || []) fails.push(x);
  r.fails = fails;
  r.verdict = fails.length ? 'FAIL' : 'PASS';
}
writeFileSync(join(out, 'findings.json'), JSON.stringify({ section, versions, tokensStatic, contrast, results }, null, 1));

// ---------- report.md ----------
const passed = results.filter((r) => r.verdict === 'PASS').length;
const built = results.filter((r) => !r.later).length;
let md = `# Design parity: section \`${section}\`\n\nDate 2026-10-28. Reference: design/option-a/mockup.html (reference images exported again this run). Larsal: offscreen snapshots of SnapshotTests.\n\n`;
md += `**Result: ${passed} of ${built} built frames PASS** (${results.length} frames in the section; ${results.length - built} belong to later stories).\n\nCheck tools: ${versions.join(', ')} (installed under /tmp/parity-tools, not in the project). Pixel diff: threshold 0.1, anti-aliasing ignored. "Outside accepted" = changed pixels left after masking the areas of accepted differences and live values (window buttons, strength words and meters, counts, codes, countdowns, times, paths).\n\n`;
md += `| Frame | Light | Dark | Pixels light / dark (outside accepted) | Missing strings | Token mismatches | Boxes / text runs > 2 pt (light, dark) | Verdict |\n|---|---|---|---|---|---|---|---|\n`;
for (const r of results) {
  if (r.later) { md += `| ${r.id} | – | – | – | – | – | – | ${r.verdict} |\n`; continue; }
  const L = r.themes.light, D = r.themes.dark;
  const px = pixelText;
  const miss = (t) => (t.present ? t.text.missing.map((x) => x.m) : []);
  const tok = (t) => (t.colours ? t.colours.issues.length + t.icons.missing.length : 0);
  md += `| ${r.id} | ${L.present ? 'present' : 'MISSING'} | ${D.present ? 'present' : 'MISSING'} | ${px(L)} / ${px(D)} | ${[...new Set([...miss(L), ...miss(D)])].map((s) => '"' + s + '"').join(', ') || '0'} | ${tok(L)} / ${tok(D)} | ${L.geoFails ?? '–'} + ${L.runFails ?? '–'} / ${D.geoFails ?? '–'} + ${D.runFails ?? '–'} | ${r.verdict} |\n`;
}
md += `\nToken mismatches = colours whose share of the frame differs (missing or extra, at least 0.5 % of the pixels) plus Phosphor glyphs the app does not draw. Static token check (every colour asset against app.css): ${tokensStatic.filter((x) => x.ok).length} of ${tokensStatic.length} equal${tokensStatic.some((x) => !x.ok) ? '; differing: ' + tokensStatic.filter((x) => !x.ok).map((x) => `${x.name} (css ${x.light}/${x.dark}, app ${x.larsal_light}/${x.larsal_dark})`).join('; ') : ''}.\n\n`;
md += `## Findings per frame\n\n`;
for (const r of results) {
  md += `### ${r.id}: ${r.verdict}\n\n`;
  if (r.later) { md += `Not built yet: ${r.later}. Not checked.\n\n`; continue; }
  const note = NOTES[r.id] || {};
  for (const x of r.fails) md += `- FAIL: ${x}\n`;
  for (const x of r.measured || []) md += `- ${x}\n`;
  for (const x of note.summary || []) md += `- ${x}\n`;
  for (const th of THEMES) { const t = r.themes[th]; if (t.shifted?.length || t.shiftedRuns?.length) md += `- ${th}: recorded shift (${(note.geoShift || []).map((z) => `${z.dy} pt, ${z.ref}`).join('; ')}) applies to ${t.shifted.length} boxes and ${t.shiftedRuns.length} text runs; left after the shift, at most ${Math.max(0, ...t.shifted.map((g) => worst(g.rest)), ...t.shiftedRuns.map((x) => Math.max(...x.rest.map(Math.abs))))} pt.\n`; }
  if (note.fix) md += `- Smallest fix: ${note.fix}\n`;
  md += `\nImages: light \`${r.themes.light.appImg}\` against \`${r.themes.light.refImg}\`, diff \`${r.themes.light.diffImg}\`; dark likewise.\n\n`;
}
const low = contrast.filter((c) => c.ratio < 4.5);
md += `## Contrast (check 7)\n\nToken pairs that carry words, WCAG ratio, both themes: ${contrast.length} pairs, lowest ${Math.min(...contrast.map((c) => c.ratio))}:1; under 4.5:1: ${low.length ? low.map((c) => `${c.theme} ${c.pair} ${c.ratio}:1`).join(', ') : 'none'}.\n\n`;
md += `## Commands run\n\n${COMMANDS}\n\nThis report: \`node design/parity/tools/compare.mjs ${section}\` printed:\n\n\`\`\`\n${section}: ${passed}/${built} PASS\n${results.map((r) => `${r.id.padEnd(46)} ${r.verdict.padEnd(22)} L ${pixelText(r.themes.light)} D ${pixelText(r.themes.dark)}`).join('\n')}\n\`\`\`\n`;
writeFileSync(join(out, 'report.md'), md);

// ---------- report.html ----------
const list = (xs, f = (x) => esc(x)) => (xs.length ? `<ul>${xs.map((x) => `<li>${f(x)}</li>`).join('')}</ul>` : '<p class="ok">none</p>');
let html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Design parity: ${esc(section)}</title><style>
body{font:14px/1.45 system-ui,sans-serif;margin:24px 32px;color:#131416;background:#f6f7f7}h1{font-size:22px}h2{font-size:18px;margin-top:40px}h3{font-size:15px;margin:20px 0 6px}
table{border-collapse:collapse;background:#fff}td,th{border:1px solid #dfe2e3;padding:4px 8px;text-align:left;vertical-align:top;font-size:13px}
.trio{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.trio figure{margin:0}.trio img{width:100%;border:1px solid #ccc;background:#fff}.trio figcaption{font-size:12px;color:#5d6062}
.PASS{color:#1e7b4f;font-weight:600}.FAIL{color:#c4242a;font-weight:600}.later{color:#5d6062;font-weight:600}.ok{color:#1e7b4f;margin:0}section.frame{background:#fff;border:1px solid #dfe2e3;border-radius:8px;padding:16px 20px;margin:24px 0}
details{margin:6px 0}summary{cursor:pointer;font-weight:600}code{font-size:12px}ul{margin:4px 0 8px;padding-left:20px}
</style></head><body><h1>Design parity: section <code>${esc(section)}</code></h1>
<p>Date 2026-10-28. ${passed} of ${built} built frames PASS. Check tools: ${esc(versions.join(', '))}. Pixel diff threshold 0.1, anti-aliasing ignored. The summary table and the commands are in <a href="report.md">report.md</a>; the raw numbers in <a href="findings.json">findings.json</a>.</p>
<table><tr><th>Frame</th><th>Pixels light</th><th>Pixels dark</th><th>Verdict</th></tr>${results.map((r) => `<tr><td><a href="#${r.id}">${r.id}</a></td><td>${r.later ? '–' : esc(pixelText(r.themes.light))}</td><td>${r.later ? '–' : esc(pixelText(r.themes.dark))}</td><td class="${r.later ? 'later' : r.verdict}">${esc(r.verdict)}</td></tr>`).join('')}</table>`;
for (const r of results) {
  const note = NOTES[r.id] || {};
  html += `<section class="frame" id="${r.id}"><h2>${esc(r.id)} <span class="${r.later ? 'later' : r.verdict}">${esc(r.verdict)}</span></h2><p>${esc(r.title)} · ${esc(r.note)}</p>`;
  if (r.later) { html += `<p>Built by a later story (${esc(r.later)}); not checked.</p></section>`; continue; }
  if (r.fails.length) html += `<h3>Why FAIL</h3>${list(r.fails)}`;
  if (r.measured?.length) html += `<h3>Measured looks (LD-169)</h3>${list(r.measured)}`;
  if (note.summary) html += `<h3>Verify notes</h3>${list(note.summary)}`;
  for (const th of THEMES) { const t = r.themes[th]; if (t.shifted?.length) html += `<details><summary>${th}: boxes under the recorded shift (${(note.geoShift || []).map((z) => `${z.dy} pt, ${esc(z.ref)}`).join('; ')})</summary>${list([...t.shifted.map((g) => `${g.kind} "${g.text}": Δ ${g.d.join(', ')} → after the shift ${g.rest.join(', ')}`), ...t.shiftedRuns.map((x) => `text "${x.text}": Δ ${x.d.slice(0, 2).join(', ')} → ${x.rest.join(', ')}`)], esc)}</details>`; }
  if (note.fix) html += `<p><b>Smallest fix:</b> ${esc(note.fix)}</p>`;
  for (const theme of THEMES) {
    const t = r.themes[theme];
    html += `<h3>${theme}</h3>`;
    if (!t.present) { html += `<p class="FAIL">1. Present: FAIL, no app snapshot.</p>`; continue; }
    html += `<div class="trio"><figure><img loading="lazy" src="${t.refImg}" alt="mockup ${theme}"><figcaption>Mockup</figcaption></figure><figure><img loading="lazy" src="${t.appImg}" alt="app ${theme}"><figcaption>Larsal</figcaption></figure><figure><img loading="lazy" src="${t.diffImg}" alt="diff ${theme}"><figcaption>Diff: ${t.sizeOk ? `${t.pixels} % changed, ${t.residual} % outside accepted areas` : pixelText(t)}</figcaption></figure></div>`;
    const tx = t.text;
    html += `<p><b>1. Present:</b> yes (${theme}, ${r.size.join(' × ')} pt, image size ${t.sizeOk ? 'equal' : 'DIFFERENT'}).</p>`;
    html += `<p><b>2. Text:</b> ${tx.found.length} found in the accessibility tree, ${tx.accepted.length} accepted differences, ${tx.live.length} live values (format), ${tx.clipped.length} clipped in the mockup, ${tx.drawnOnly.length} drawn but not in the tree, ${tx.behind.length} behind an open menu, <b>${tx.missing.length} missing</b>.</p>`;
    html += `<details><summary>Missing (${tx.missing.length})</summary>${list(tx.missing, (x) => `${esc(x.m)} <i>(${x.kind})</i>`)}</details>`;
    html += `<details><summary>Accepted (${tx.accepted.length}) and live (${tx.live.length})</summary>${list([...tx.accepted, ...tx.live], (x) => `"${esc(x.m)}" → "${esc(x.app ?? 'n/a')}": ${esc(x.why)} ${x.ref ? '(' + esc(x.ref) + ')' : ''}`)}</details>`;
    html += `<details><summary>Drawn, not in the accessibility tree (${tx.drawnOnly.length})</summary>${list(tx.drawnOnly, (x) => `"${esc(x.m)}" (read from the picture as "${esc(x.ocr)}")`)}</details>`;
    html += `<details><summary>Behind an open modal menu (${tx.behind.length})</summary>${list(tx.behind, (x) => `"${esc(x.m)}": not in the tree while the menu is open (VoiceOver stays in the menu); the same view without the menu has it (${esc(x.frame)})`)}</details>`;
    html += `<details><summary>Clipped in the mockup (${tx.clipped.length})</summary>${list(tx.clipped, (x) => esc(x.m))}</details>`;
    html += `<details><summary>Extra strings in the app (${tx.extra.length}) and help texts (${tx.help.length})</summary>${list(tx.extra)}${list(tx.help)}</details>`;
    // No colour shares when the image sizes differ (item 1 says so).
    const c = t.colours || { issues: [], major: [] };
    html += `<p><b>3. Tokens:</b> colours ${c.issues.length ? `<span class="FAIL">${c.issues.length} differ</span>` : 'match'}; glyphs ${t.icons.used.length} used, ${t.icons.missing.length ? `<span class="FAIL">not drawn: ${esc(t.icons.missing.join(', '))}</span>` : 'all drawn'}; brand logos ${esc(t.icons.logos.join(', ') || 'none')}${t.icons.noLogo.length ? `, no asset: ${esc(t.icons.noLogo.join(', '))}` : ''}.</p>`;
    html += `<details><summary>Main colours (share of pixels, mockup → app)</summary>${list(c.major, (x) => `${x.hex} ${esc(x.token || '')}: ${x.ref} % → ${x.app} %`)}${c.issues.length ? '<p>Differing:</p>' + list(c.issues, (x) => `${x.kind} ${x.hex} ${esc(x.token || '')}: ${x.ref} % → ${x.app} %`) : ''}</details>`;
    const geo = t.geometry.filter((g) => g.d);
    const off = geo.filter((g) => worst(g.d) > 2);
    html += `<p><b>4. Geometry:</b> ${geo.length} boxes compared, ${off.length ? `<span class="FAIL">${off.length} off by more than 2 pt</span>` : 'all within 2 pt'}${t.sheet ? `; sheet edges mockup ${esc(JSON.stringify(t.sheet.ref))}, app ${esc(JSON.stringify(t.sheet.app))}` : ''}.</p>`;
    html += `<details><summary>Boxes (x, y, w, h in pt; Δ = app − mockup)</summary><table><tr><th>Kind</th><th>Text</th><th>Mockup</th><th>Larsal</th><th>Δ</th></tr>${t.geometry.map((g) => `<tr><td>${g.kind}</td><td>${esc(g.text)}</td><td>${g.dom.join(', ')}</td><td>${g.app ? g.app.join(', ') : esc(g.note || 'no counterpart')}</td><td class="${g.d && worst(g.d) > 2 ? 'FAIL' : ''}">${g.d ? g.d.join(', ') : ''}</td></tr>`).join('')}</table></details>`;
    const runsOff = t.runs.filter((x) => Math.max(Math.abs(x.d[0]), Math.abs(x.d[1])) > 2);
    html += `<details><summary>Text runs (${t.runs.length} matched by their words, ${runsOff.length} placed more than 2 pt off; widths and heights differ by the text engines and are not judged)</summary><table><tr><th>Text</th><th>Mockup font</th><th>Mockup</th><th>Larsal</th><th>Δ</th></tr>${runsOff.map((x) => `<tr><td>${esc(x.text)}</td><td>${esc(x.font)}</td><td>${x.dom.join(', ')}</td><td>${x.app.join(', ')}</td><td>${x.d.join(', ')}</td></tr>`).join('')}</table></details>`;
    if (!t.sizeOk) html += `<p><b>5. Pixels:</b> ${pixelText(t)}.</p>`;
    else html += `<p><b>5. Pixels:</b> ${t.pixels} % changed (${t.residual} % outside accepted areas): ${t.pixels <= 3 ? 'within 3 %' : t.residual <= 3 ? 'over 3 %, all but ' + t.residual + ' % in accepted areas' : '<span class="FAIL">over 3 %</span>'}.</p>`;
    html += `<p><b>7. Accessibility:</b> ${t.unnamed.length ? `<span class="FAIL">${t.unnamed.length} unnamed controls</span>` : 'every control has a name'}; disabled (later stories): ${t.disabled.length}.</p>`;
  }
  html += `<h3>6. Behaviour</h3><p>Mockup controls in this frame: ${r.controls.length}.</p>${list(r.controls)}<p>Tests (ParityTests, offscreen, pressed through the accessibility tree):</p>${list(r.behaviour, (b) => `<span class="${b.ok ? 'PASS' : 'FAIL'}">${b.ok ? 'pass' : 'FAIL'}</span> ${esc(b.name)}`)}</section>`;
}
html += `<h2>Contrast (check 7)</h2><table><tr><th>Theme</th><th>Pair</th><th>Ratio</th></tr>${contrast.map((c) => `<tr><td>${c.theme}</td><td>${c.pair}</td><td class="${c.ratio < 4.5 ? 'FAIL' : 'PASS'}">${c.ratio}:1</td></tr>`).join('')}</table>`;
html += `<h2>Static token check</h2><table><tr><th>Token</th><th>css light</th><th>app light</th><th>css dark</th><th>app dark</th><th></th></tr>${tokensStatic.map((x) => `<tr><td>${x.name}</td><td>${x.light}</td><td>${x.larsal_light ?? x.app}</td><td>${x.dark}</td><td>${x.larsal_dark ?? ''}</td><td class="${x.ok ? 'PASS' : 'FAIL'}">${x.ok ? 'equal' : 'differs'}</td></tr>`).join('')}</table></body></html>`;
writeFileSync(join(out, 'report.html'), html);
console.log(`${section}: ${passed}/${built} PASS`);
for (const r of results) console.log(`${r.id.padEnd(46)} ${r.verdict.padEnd(22)} L ${pixelText(r.themes.light)} D ${pixelText(r.themes.dark)} ${r.fails?.join(' | ') ?? ''}`);
