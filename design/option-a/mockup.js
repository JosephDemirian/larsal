'use strict';
/* Larsal · Option A mockup. Every window of the Mac app, light and dark, from one set of parts.
   Demo data only. "Now" is fixed so every screen reads the same on each load. */

const NOW = new Date('2026-10-27T10:30:00');
const W = 1320, H = 820; // main window size used for every main-window frame

// ---------- data ----------
const VAULTS = [
  { id: 'personal', name: 'Personal', file: 'Personal.larsalvault', path: '~/Documents/Passwords/Personal.larsalvault', c: '--teal', icon: 'keyhole', saved: '08:50' },
  { id: 'work', name: 'Work', file: 'Work.larsalvault', path: '~/Documents/Passwords/Work.larsalvault', c: '--orange', icon: 'briefcase', locked: true },
  { id: 'family', name: 'Family', file: 'Family.larsalvault', path: '~/Library/Mobile Documents/Family.larsalvault', c: '--pink', icon: 'users-three', locked: true },
];
const LIB = [
  { id: 'all', label: 'All entries', icon: 'tray', c: '--blue' },
  { id: 'fav', label: 'Favorites', icon: 'star', c: '--orange' },
  { id: 'codes', label: 'One-time codes', icon: 'clock-countdown', c: '--teal' },
  { id: 'passkeys', label: 'Passkeys', icon: 'fingerprint', c: '--purple' },
  { id: 'health', label: 'Password health', icon: 'shield-warning', c: '--red' },
];
const GROUPS = [
  { id: 'email', name: 'Email', icon: 'envelope-simple', c: '--blue' },
  { id: 'banking', name: 'Banking', icon: 'bank', c: '--green' },
  { id: 'social', name: 'Social', icon: 'users-three', c: '--pink' },
  { id: 'shopping', name: 'Shopping', icon: 'shopping-bag', c: '--orange' },
  { id: 'work', name: 'Work', icon: 'briefcase', c: '--brown' },
  { id: 'servers', name: 'Servers', icon: 'hard-drives', c: '--slate', parent: 'work' },
  { id: 'devices', name: 'Devices', icon: 'wifi-high', c: '--cyan' },
];
const TAGS = [['2fa', '--teal'], ['dev', '--purple'], ['finance', '--green'], ['shared', '--orange'], ['ssh', '--slate']];

const E = (o) => Object.assign({ kind: 'login', username: '', password: '', url: '', tags: [], files: [], notes: '', group: 'root', hist: 0, fav: false }, o);
const ENTRIES = [
  E({ id: 'github', title: 'GitHub', brand: 'github', username: 'alex-dev', password: 'x9!Lq#4vT@m2Zr8&Wk5p', url: 'https://github.com/login', group: 'work', tags: ['2fa', 'dev'], created: '2024-03-03T10:12', modified: '2026-10-22T08:49', totp: 'github', passkey: 'github.com', notes: 'Recovery codes are in the attachment.\nOrganization: morgan-labs', files: [{ name: 'github-recovery-codes.txt', size: '1.2 KB' }], hist: 3, fav: true, allow: ['github.com', 'gist.github.com'] }),
  E({ id: 'apple', title: 'Apple Account', brand: 'apple', username: 'alex.morgan@icloud.com', password: 'Ap4!Kz8@Rq2#Wn6$', url: 'https://account.apple.com', created: '2022-11-02T12:00', modified: '2026-10-21T18:02', passkey: 'apple.com', hist: 2, fav: true }),
  E({ id: 'google', title: 'Google', brand: 'google', username: 'alex.morgan@gmail.com', password: 'Hn7$wQ2!cV9#tR4@yB6x', url: 'https://accounts.google.com', group: 'email', tags: ['2fa'], created: '2021-05-14T09:30', modified: '2026-10-20T14:31', totp: 'google', hist: 4, fav: true, allow: ['accounts.google.com'] }),
  E({ id: 'hetzner', title: 'Hetzner Cloud', brand: 'hetzner', username: 'alex@morgan-labs.dev', password: 'Vm2#Kq8!Rt5@Ls9$Xw', url: 'https://console.hetzner.cloud', group: 'servers', tags: ['2fa', 'dev'], created: '2025-02-11T16:45', modified: '2026-10-18T11:05', totp: 'hetzner', hist: 1 }),
  E({ id: 'proton', title: 'Proton Mail', brand: 'protonmail', username: 'alex.morgan@proton.me', password: 'violet anchor mosaic tundra lantern quill harbor', url: 'https://account.proton.me/login', group: 'email', tags: ['2fa'], created: '2023-08-19T20:10', modified: '2026-10-14T20:40', totp: 'proton', hist: 1, fav: true }),
  E({ id: 'web01', kind: 'ssh', title: 'Server root · web-01', icon: 'terminal-window', c: '--graphite', username: 'root', password: 'glacier pepper canyon ribbon falcon', url: 'ssh://203.0.113.10', group: 'servers', tags: ['dev', 'ssh'], created: '2025-06-02T08:00', modified: '2026-10-11T16:20', notes: 'Falkenstein, 2 vCPU.\nThe password unlocks the private key.', files: [{ name: 'id_ed25519', size: '464 B' }, { name: 'id_ed25519.pub', size: '98 B' }] }),
  E({ id: 'paypal', title: 'PayPal', brand: 'paypal', username: 'alex.morgan@posteo.de', password: 'Gk3@vN8!sL5#qT1$', url: 'https://www.paypal.com/signin', group: 'banking', tags: ['finance'], created: '2019-04-20T10:00', modified: '2026-10-09T09:15', hist: 2 }),
  E({ id: 'instagram', title: 'Instagram', brand: 'instagram', username: 'alex.morgan.photos', password: 'Pb5$Lx9!Wd3@Nz7#', url: 'https://www.instagram.com', group: 'social', tags: ['2fa'], created: '2020-07-07T21:00', modified: '2026-10-02T19:44', totp: 'insta', hist: 1 }),
  E({ id: 'wise', title: 'Wise', brand: 'wise', username: 'alex.morgan@posteo.de', password: 'Tz4#pW9@kM2!xF7&', url: 'https://wise.com/login', group: 'banking', tags: ['2fa', 'finance'], created: '2022-01-10T11:00', modified: '2026-09-28T17:05', totp: 'wise', hist: 1 }),
  E({ id: 'figma', title: 'Figma', brand: 'figma', username: 'alex@morgan-labs.dev', password: 'Fy6@Tn1!Qp8#Hc4$', url: 'https://www.figma.com/login', group: 'work', created: '2023-04-01T09:00', modified: '2026-09-22T10:10', allow: ['www.figma.com'] }),
  E({ id: 'mastodon', title: 'Mastodon', brand: 'mastodon', username: '@alex@mastodon.social', url: 'https://mastodon.social', group: 'social', created: '2026-09-18T22:00', modified: '2026-09-18T22:00', passkey: 'mastodon.social' }),
  E({ id: 'linear', title: 'Linear', brand: 'linear', username: 'alex@morgan-labs.dev', password: 'Lr3#Vb7!Mk1@Zp5$', url: 'https://linear.app/login', group: 'work', created: '2024-09-09T09:00', modified: '2026-09-15T14:00', passkey: 'linear.app', hist: 1 }),
  E({ id: 'visa', kind: 'card', title: 'Visa Debit', brand: 'visa', username: 'Card ending 1111', group: 'banking', tags: ['finance'], created: '2024-10-01T09:00', modified: '2026-09-10T08:30', notes: 'Lost card: call the number on the back.', card: { holder: 'ALEX MORGAN', number: '4111 1111 1111 1111', expiry: '09/29', cvv: '123', pin: '4821' } }),
  E({ id: 'zalando', title: 'Zalando', brand: 'zalando', username: 'alex.morgan@posteo.de', password: 'Rq8!nV3@hK6#', url: 'https://www.zalando.de/login', group: 'shopping', created: '2021-03-15T18:00', modified: '2026-09-02T12:30', expires: '2026-10-01' }),
  E({ id: 'amazon', title: 'Amazon', username: 'alex.morgan@posteo.de', password: 'Summer2024!', url: 'https://www.amazon.de/ap/signin', group: 'shopping', created: '2018-12-01T12:00', modified: '2026-08-27T20:15', hist: 2, deny: ['www.amazon.com'] }),
  E({ id: 'bahn', title: 'Deutsche Bahn', brand: 'deutschebahn', username: 'alex.morgan@posteo.de', password: 'Db5@Hx1!Mq7#Tv3$', url: 'https://www.bahn.de', created: '2022-06-06T07:00', modified: '2026-08-19T07:45' }),
  E({ id: 'slack', title: 'Slack', username: 'alex@morgan-labs.dev', password: 'morganlabs2024', url: 'https://morgan-labs.slack.com', group: 'work', created: '2023-02-02T09:00', modified: '2026-08-04T09:30' }),
  E({ id: 'ebay', title: 'eBay', brand: 'ebay', username: 'alexmorgan88', password: 'Summer2024!', url: 'https://signin.ebay.de', group: 'shopping', created: '2017-05-05T15:00', modified: '2026-07-21T18:00', hist: 1 }),
  E({ id: 'aws', title: 'AWS root account', username: 'alex@morgan-labs.dev', password: 'Aw7$Pq3!Zr9@Lm5#Ty2&', url: 'https://console.aws.amazon.com', group: 'servers', tags: ['2fa', 'dev'], created: '2024-01-15T10:00', modified: '2026-07-08T13:20', totp: 'aws', notes: 'Use IAM users for daily work. Root only for billing.', hist: 2 }),
  E({ id: 'netflix', title: 'Netflix', brand: 'netflix', username: 'family.morgan@posteo.de', password: 'Nf8#Qr2!Lz6@Pv4$', url: 'https://www.netflix.com/login', tags: ['shared'], created: '2020-02-14T20:00', modified: '2026-06-30T21:10' }),
  E({ id: 'reddit', title: 'Reddit', brand: 'reddit', username: 'alex_m', password: 'sunshine2019', url: 'https://www.reddit.com/login', group: 'social', created: '2019-03-03T23:00', modified: '2026-06-12T22:40' }),
  E({ id: 'wifi', kind: 'wifi', title: 'Home Wi-Fi', icon: 'wifi-high', c: '--cyan', username: 'Morgan-Home 5G', password: 'harbor velvet orchid meteor pine', group: 'devices', tags: ['shared'], created: '2024-05-03T18:00', modified: '2026-05-03T18:20', notes: 'Guest network: Morgan-Guest', fav: true }),
  E({ id: 'router', title: 'Router admin', icon: 'hard-drives', c: '--slate', username: 'admin', password: 'admin1234', url: 'http://192.168.178.1', group: 'devices', created: '2021-09-09T09:00', modified: '2026-02-14T10:00' }),
  E({ id: 'twitter', title: 'Twitter (old account)', brand: 'x', username: '@alexmorgan', password: 'Tw9!xK2@pL7#', url: 'https://x.com/login', group: 'bin', from: 'social', created: '2014-06-01T12:00', modified: '2026-10-03T19:00', deleted: '2026-10-03T19:00' }),
  E({ id: 'myspace', title: 'MySpace', username: 'alexm1999', password: 'qwerty123', url: 'https://myspace.com', group: 'bin', from: 'social', created: '2008-01-01T12:00', modified: '2026-09-12T08:00', deleted: '2026-09-12T08:00' }),
];
const HISTORY = [
  { when: '2026-10-22T08:49', what: 'Passkey added', pw: false },
  { when: '2026-06-03T11:20', what: 'Password changed', pw: true },
  { when: '2024-03-03T10:12', what: 'Entry created', pw: true },
];
const WORDS = 'anchor amber basin beacon birch canyon cedar cinder comet coral dune ember falcon fjord garnet glacier harbor hazel island jasper juniper kettle lagoon lantern maple meadow meteor mosaic nectar oasis orchid pebble pepper quartz quill raven ribbon saffron sierra spruce summit thistle timber tundra velvet violet willow yarrow zephyr'.split(' ');

// ---------- checks (computed from the rows) ----------
const COMMON = /(summer|winter|password|qwerty|admin|sunshine|letmein|morgan|printer|1234|2019|2024)/i;
const live = ENTRIES.filter((e) => e.group !== 'bin');
const bin = ENTRIES.filter((e) => e.group === 'bin');
const byId = (id) => ENTRIES.find((e) => e.id === id);
const groupOf = (id) => GROUPS.find((g) => g.id === id);
function bits(pw) {
  if (!pw) return 0;
  const words = pw.trim().split(/\s+/);
  if (words.length >= 4) return Math.round(words.length * 12.9);
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const raw = pw.length * Math.log2(pool);
  return Math.round(COMMON.test(pw) ? Math.min(raw, 28) : raw);
}
const reuse = {};
live.forEach((e) => { if (e.password) (reuse[e.password] = reuse[e.password] || []).push(e.id); });
function check(e) {
  if (e.kind === 'card') return { level: 'none', word: '—', seg: 0 };
  if (!e.password) return { level: 'none', word: e.passkey ? 'Passkey only' : '—', seg: 0 };
  const b = bits(e.password), others = (reuse[e.password] || []).filter((id) => id !== e.id);
  if (e.expires && new Date(e.expires) < NOW) return { level: 'warn', word: 'Expired', issue: 'Expired', seg: 2, b, why: `This password expired on ${fmtDay(e.expires)}.` };
  if (others.length) return { level: 'bad', word: 'Reused', issue: 'Reused', seg: b < 40 ? 1 : 2, b, why: `${others.map((id) => byId(id).title).join(', ')} uses the same password.`, others };
  if (b < 40) return { level: 'bad', word: 'Weak', issue: 'Weak', seg: 1, b, why: 'Short and built from a common word and a year.' };
  if (b < 64) return { level: 'ok', word: 'Fair', seg: 3, b };
  return { level: 'ok', word: 'Strong', seg: 4, b };
}
const isBad = (e) => ['bad', 'warn'].includes(check(e).level);
const attention = () => live.filter(isBad);

// One-time codes: demo values that change every 30 s (the app computes RFC 6238 codes in Rust).
function code(seed, step) { let h = 2166136261; for (const c of seed + ':' + step) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return String((h >>> 0) % 1e6).padStart(6, '0'); }
const fmtCode = (c) => c.slice(0, 3) + ' ' + c.slice(3);
// ?t=<ms> freezes the clock so exported references are identical on every run.
const FROZEN = +new URLSearchParams(location.search).get('t') || 0;
const clock = () => FROZEN || Date.now();
const step = () => Math.floor(clock() / 30000);

// ---------- format ----------
const MONTH = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
const fmtDay = (s) => new Date(s).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
const fmtDate = (s) => new Date(s).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
const fmtTime = (s) => String(s).slice(11, 16);
function fmtMod(s) {
  const d = new Date(s), days = Math.floor((new Date(NOW.toDateString()) - new Date(d.toDateString())) / 864e5);
  if (days === 0) return 'Today'; if (days === 1) return 'Yesterday'; if (days < 7) return days + ' days';
  return d.getFullYear() === NOW.getFullYear() ? fmtDay(s) : fmtDate(s);
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const host = (u) => { try { return new URL(u).host || u; } catch { return u; } };
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// ---------- parts ----------
const ic = (n, cls = '') => `<i class="ph ph-${n} ${cls}" aria-hidden="true"></i>`;
const icf = (n, cls = '') => `<i class="ph-fill ph-${n} ${cls}" aria-hidden="true"></i>`;
const tile = (c, icon, size = '') => `<span class="tile ${size}" style="--c:var(${c})">${icf(icon)}</span>`;
const ibtn = (icon, label, a = '', v = '', cls = '') => `<button class="ibtn ${cls}" aria-label="${label}" title="${label}"${a ? ` data-a="${a}"` : ''}${v ? ` data-v="${v}"` : ''}>${ic(icon)}</button>`;
const sw = (on, label) => `<button class="sw" role="switch" aria-checked="${!!on}" aria-label="${label}" data-a="sw"></button>`;
const cb = (on) => `<span class="cb" role="checkbox" aria-checked="${!!on}"></span>`;
const rb = (on) => `<span class="rb" role="radio" aria-checked="${!!on}"></span>`;
const selx = (v) => `<span class="selx">${v}${ic('caret-up-down')}</span>`;
const stepper = (v, unit = '') => `<span class="step"><span class="num">${v}${unit ? ' ' + unit : ''}</span><button aria-label="Less">${ic('minus')}</button><button aria-label="More">${ic('plus')}</button></span>`;
const kbd = (k) => `<span class="kbd">${k}</span>`;
function lum(hex) { const n = parseInt(hex, 16), r = (n >> 16) / 255, g = ((n >> 8) & 255) / 255, b = (n & 255) / 255; return 0.2126 * r + 0.7152 * g + 0.0722 * b; }
function brandSvg(key, size) {
  const b = window.BRANDS[key]; if (!b) return '';
  return `<svg viewBox="0 0 24 24" role="img" aria-label="${esc(b.title)}"${size ? ` style="width:${size}px;height:${size}px"` : ''}><path class="${lum(b.hex) < 0.18 ? 'dk' : ''}" fill="#${b.hex}" d="${b.path}"/></svg>`;
}
function hue(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; }
function logo(e, size = '') {
  if (e.brand && window.BRANDS[e.brand]) return `<span class="logo ${size}">${brandSvg(e.brand)}</span>`;
  if (e.icon) return `<span class="logo tinted ${size}" style="--c:var(${e.c || '--gray'})">${icf(e.icon)}</span>`;
  return `<span class="logo letter ${size}" style="--h:${hue(e.title)}" aria-hidden="true">${esc(e.title[0])}</span>`;
}
const pwHtml = (pw) => [...pw].map((c) => /\d/.test(c) ? `<span class="d">${c}</span>` : /[a-zA-Z\s]/.test(c) ? esc(c) : `<span class="s">${esc(c)}</span>`).join('');
const dots = (n) => '•'.repeat(Math.min(n, 18));
const meter = (seg) => `<span class="meter" aria-hidden="true">${[1, 2, 3, 4].map((i) => `<i class="${i <= seg ? 'on' : ''}"></i>`).join('')}</span>`;
function qr(seed, size = 176) {
  const n = 29, cell = size / n; let h = hue(seed) + 7, out = '';
  const finder = (x, y) => `<rect x="${x * cell}" y="${y * cell}" width="${7 * cell}" height="${7 * cell}" fill="currentColor"/><rect x="${(x + 1) * cell}" y="${(y + 1) * cell}" width="${5 * cell}" height="${5 * cell}" fill="var(--surface)"/><rect x="${(x + 2) * cell}" y="${(y + 2) * cell}" width="${3 * cell}" height="${3 * cell}" fill="currentColor"/>`;
  for (let y = 0; y < n; y++) for (let x = 0; x < n; x++) {
    if ((x < 8 && y < 8) || (x > n - 9 && y < 8) || (x < 8 && y > n - 9)) continue;
    h = (h * 1103515245 + 12345) & 0x7fffffff;
    if (h % 7 < 3) out += `<rect x="${x * cell}" y="${y * cell}" width="${cell}" height="${cell}" fill="currentColor"/>`;
  }
  return `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" role="img" aria-label="QR code" style="color:var(--text)">${out}${finder(0, 0)}${finder(n - 7, 0)}${finder(0, n - 7)}</svg>`;
}

// ---------- the main window ----------
const vaultOf = (s) => VAULTS.find((v) => v.id === (s.vault || 'personal'));
function scope(s) {
  if (s.view === 'bin') return bin;
  if (s.view === 'all' || !s.view) return live;
  if (s.view === 'fav') return live.filter((e) => e.fav);
  if (s.view === 'codes') return live.filter((e) => e.totp);
  if (s.view === 'passkeys') return live.filter((e) => e.passkey);
  if (s.view.startsWith('tag:')) return live.filter((e) => e.tags.includes(s.view.slice(4)));
  const kids = GROUPS.filter((g) => g.parent === s.view).map((g) => g.id);
  return live.filter((e) => e.group === s.view || kids.includes(e.group));
}
const TABS = [['all', 'All', () => true], ['totp', 'Two-step codes', (e) => e.totp], ['passkey', 'Passkeys', (e) => e.passkey], ['attention', 'Needs attention', isBad]];
function visible(s) {
  const f = (TABS.find((t) => t[0] === s.tab) || TABS[0])[2], q = (s.q || '').toLowerCase();
  let list = scope(s).filter(f).filter((e) => !q || (e.title + ' ' + e.username + ' ' + e.url + ' ' + e.tags.join(' ')).toLowerCase().includes(q));
  if (s.sort === 'title') list = [...list].sort((a, b) => a.title.localeCompare(b.title));
  return list;
}
function viewTitle(s) {
  const l = LIB.find((x) => x.id === s.view), g = groupOf(s.view);
  if (s.view === 'bin') return 'Recycle Bin';
  if (s.view && s.view.startsWith('tag:')) return '#' + s.view.slice(4);
  return l ? l.label : g ? g.name : 'All entries';
}

function shell(s) {
  if (s.mode === 'locked') return lockedWindow(s);
  return `<div class="shell">
    <div class="tb"><div class="left"><div class="lights"><i></i><i></i><i></i></div>${ibtn('sidebar-simple', 'Hide sidebar (⌃⌘S)')}</div>
      ${searchBox(s)}
      <div class="right"><button class="btn" data-a="lock">${ic('lock-simple')}Lock ${kbd('⌘L')}</button></div></div>
    ${sidebar(s)}
    <main class="sheet">${s.mode === 'editor' ? editorView(s) : s.mode === 'reports' ? reportsView(s) : s.mode === 'empty' ? emptyVault(s) : listView(s)}</main>
  </div>${overlays(s)}${s.toast ? `<div class="toast" role="status">${s.toast}</div>` : ''}${s.dialog ? `<div class="scrim">${DIALOGS[s.dialog]()}</div>` : ''}`;
}
function searchBox(s) {
  const v = vaultOf(s);
  return `<label class="search">${ic('magnifying-glass')}<input data-a="q" value="${esc(s.q || '')}" placeholder="Search ${esc(v.name)}…" aria-label="Search entries" autocomplete="off" spellcheck="false">${s.q ? ibtn('x-circle', 'Clear search', 'clearq', '', 'sm') : kbd('⌘F')}
    ${s.overlay === 'tips' ? `<div class="tips"><div class="mh">Search tips</div>${[['is:weak', 'Weak, reused or expired passwords'], ['is:expired', 'Entries past their expiry date'], ['group:Work', 'Entries in a group and its subgroups'], ['url:github', 'Only the website field'], ['tag:2fa', 'Entries with a tag'], ['-amazon', 'Leave out entries with this word'], ['"exact words"', 'Match the words in this order']].map(([k, d]) => `<div class="ti"><code>${k}</code><span>${d}</span></div>`).join('')}</div>` : ''}</label>`;
}
function sidebar(s) {
  const v = vaultOf(s), empty = s.mode === 'empty', L = empty ? [] : live, att = L.filter(isBad).length;
  const counts = { all: L.length, fav: L.filter((e) => e.fav).length, codes: L.filter((e) => e.totp).length, passkeys: L.filter((e) => e.passkey).length };
  const cur = (id) => (s.view === id || (id === 'health' && s.mode === 'reports')) && s.mode !== 'editor-x' ? ' aria-current="page"' : '';
  const item = (id, label, inner, extra = '', cls = '') => `<li><button class="si ${cls}" data-a="view" data-v="${id}"${cur(id)}>${inner}<span class="lbl">${label}</span>${extra}</button></li>`;
  const gcount = (g) => scope({ view: g.id }).length;
  return `<aside class="sb" aria-label="Sidebar">
    <button class="vsw" data-a="menu" data-v="vault" aria-label="Switch vault">${tile(v.c, v.icon, 'md')}<span class="who"><b>${v.name}</b><small>${v.file}</small></span>${ic('caret-up-down')}</button>
    <ul style="margin-top:14px">${LIB.map((l) => item(l.id, l.label, tile(l.c, l.icon), l.id === 'health' && att ? `<span class="badge num">${att}</span>` : l.id === 'health' ? '<span class="cnt num">0</span>' : `<span class="cnt num">${counts[l.id]}</span>`)).join('')}</ul>
    <div class="sb-h">Groups${ibtn('plus', 'New group', 'dialog', 'newGroup')}</div>
    ${empty ? '<p class="help" style="margin:0;padding:2px 8px">No groups yet</p>' : `<ul>${GROUPS.map((g) => item(g.id, g.name, tile(g.c, g.icon), `<span class="cnt num">${gcount(g)}</span>`, g.parent ? 'sub' : '')).join('')}</ul>`}
    <div class="sb-h"><button class="fold" data-a="tags">${ic(s.tagsOpen ? 'caret-down' : 'caret-right')}Tags</button></div>
    ${s.tagsOpen && !empty ? `<ul>${TAGS.map(([t, c]) => item('tag:' + t, t, `<span class="dot" style="--c:var(${c})"></span>`, `<span class="cnt num">${live.filter((e) => e.tags.includes(t)).length}</span>`)).join('')}</ul>` : ''}
    <div class="sb-foot"><ul>${item('bin', 'Recycle Bin', tile('--gray', 'trash'), `<span class="cnt num">${empty ? 0 : bin.length}</span>`)}<li><button class="si" data-a="settings">${tile('--graphite', 'gear-six')}<span class="lbl">Settings</span>${kbd('⌘,')}</button></li></ul>
      <div class="saved num ${s.dirty ? 'dirty' : ''}">${s.dirty ? ic('circle') + '2 changes not saved yet' : ic('check-circle') + `Saved ${v.saved ? 'at ' + v.saved : 'just now'} · encrypted`}</div></div>
  </aside>`;
}
function listView(s) {
  const list = visible(s), sc = scope(s), bad = sc.filter(isBad).length;
  if (!list.find((e) => e.id === s.sel)) s.sel = list[0] ? list[0].id : null;
  const sub = s.view === 'bin' ? `${plural(sc.length, 'entry', 'entries')} · you can restore them until you empty the bin`
    : `${plural(sc.length, 'entry', 'entries')}${bad ? ` · <b>${bad} need attention</b>` : ''}`;
  const acts = s.view === 'bin' ? `<button class="btn lg" data-a="dialog" data-v="emptyBin">${ic('trash')}Empty Recycle Bin</button>`
    : `<button class="btn lg" data-a="menu" data-v="gen">${ic('password')}Generator</button><button class="btn lg primary" data-a="new">${ic('plus')}New Entry</button>`;
  const tabs = s.view === 'bin' ? '' : TABS.map(([id, label, f]) => {
    const c = sc.filter(f).length, alert = id === 'attention' && c > 0;
    return `<button class="tab" role="tab" data-a="tab" data-v="${id}" aria-selected="${(s.tab || 'all') === id}">${label}<span class="n num${alert ? ' alert' : ''}">${c}</span></button>`;
  }).join('');
  return `<div class="trow"><div><h1>${esc(viewTitle(s))}</h1><p class="sub num">${sub}</p></div><div class="acts">${acts}</div></div>
    <div class="tabsrow"><div class="tabs" role="tablist">${tabs || '<span class="tab" aria-selected="true">Deleted entries</span>'}</div>
      <div class="end"><button class="btn ghost sm" data-a="menu" data-v="sort">${ic('sort-descending')}${s.sort === 'title' ? 'Title' : 'Modified'}</button></div></div>
    <div class="work"><section class="tbl" aria-label="Entries">
      <div class="cols thead"><span>Name</span><span class="codeh">Code <span class="tick" aria-hidden="true"><i data-tick></i></span><span class="num" data-secs-short></span></span><span>Password</span><span class="r">${s.view === 'bin' ? 'Deleted' : 'Modified'}</span></div>
      <div class="rows" role="listbox" aria-label="Entries" tabindex="0">${rows(s, list)}</div></section>
      <aside class="rail" aria-label="Entry details">${s.sel ? rail(byId(s.sel), s) : ''}</aside></div>`;
}
function rows(s, list) {
  if (!list.length) return `<div class="empty">${s.q ? `No entries match “${esc(s.q)}”. Try fewer words, or ${'<button class="link" data-a="clearq">clear the search</button>'}.` : s.tab === 'attention' ? 'Every password here is strong, unique and current.' : 'No entries here yet.'}</div>`;
  let last = '', out = '';
  for (const e of list) {
    if (s.sort !== 'title') {
      const d = new Date(e.deleted || e.modified), m = MONTH[d.getMonth()] + (d.getFullYear() !== NOW.getFullYear() ? ' ' + d.getFullYear() : '');
      if (m !== last) { out += `<div class="month">${m}</div>`; last = m; }
    }
    const c = check(e), sub = [esc(e.username || host(e.url) || '—')];
    if (e.passkey) sub.push(`${ic('fingerprint')}passkey`);
    out += `<button class="row cols" role="option" data-a="sel" data-v="${e.id}" aria-selected="${s.sel === e.id}">
      <span class="idc">${logo(e)}<span><b>${esc(e.title)}${e.fav ? ` ${icf('star', 'star')}` : ''}</b><small>${sub.join(' · ')}</small></span></span>
      <span>${e.totp ? `<span class="code num" data-totp="${e.totp}">${fmtCode(code(e.totp, step()))}</span>` : '<span class="dash">—</span>'}</span>
      <span>${c.level === 'none' ? `<span class="hl">${c.word}</span>` : `<span class="hl ${c.level}">${c.word}${meter(c.seg)}</span>`}</span>
      <span class="r mod num">${fmtMod(e.deleted || e.modified)}</span></button>`;
  }
  return out;
}
function rail(e, s) {
  if (!e) return '';
  const c = check(e), g = groupOf(e.group), cp = (w, l) => ibtn('copy', 'Copy ' + l, 'copy', w);
  const site = e.url && !e.url.startsWith('ssh') ? `<a class="site" href="#" data-a="copy" data-v="open">${esc(host(e.url))}${ic('arrow-square-out')}</a>` : `<span class="meta">${g ? g.name : 'Personal'}</span>`;
  let h = `<div class="rhead">${logo(e, 'lg')}<div style="min-width:0"><h2>${esc(e.title)}</h2>${site}</div>
    <div class="tools">${e.group === 'bin' ? '' : ibtn('pencil-simple', 'Edit entry (⌘E)', 'edit')}${ibtn('dots-three', 'More actions', 'menu', 'more')}</div></div>`;
  if (e.group === 'bin') {
    h += `<div class="notice neu">${ic('trash')}<div>Deleted on ${fmtDay(e.deleted)} from <b>${groupOf(e.from).name}</b>.<div class="acts"><button data-a="copy" data-v="restore">Restore</button><button data-a="dialog" data-v="deleteForever" style="color:var(--negative)">Delete forever</button></div></div></div>`;
  } else if (e.kind === 'login' || e.kind === 'ssh') {
    h += `<div class="quick">${e.password ? `<button class="btn" data-a="copy" data-v="password">${ic('copy')}Copy password</button>` : ''}${e.url && !e.url.startsWith('ssh') ? `<button class="btn" data-a="copy" data-v="open">${ic('arrow-square-out')}Open site</button>` : ''}${e.kind === 'ssh' ? `<button class="btn" data-a="copy" data-v="agent">${ic('terminal-window')}Load key</button>` : `<button class="btn" data-a="copy" data-v="type">${ic('keyboard')}Type login</button>`}</div>`;
  } else h += '<div style="height:16px"></div>';
  if (isBad(e) && e.group !== 'bin') h += `<div class="notice${c.level === 'warn' ? ' warn' : ''}" style="margin-top:0;margin-bottom:12px">${ic('warning-circle')}<div><b>${c.issue} password.</b> ${c.why}<div class="acts"><button data-a="edit">Change password</button><button data-a="mode" data-v="reports">Open report</button></div></div></div>`;
  h += '<div class="panel">';
  if (e.kind === 'card') {
    const k = e.card;
    h += fld('Cardholder', esc(k.holder)) + fld('Card number', `<span class="pw">${s.reveal ? k.number : '•••• •••• •••• ' + k.number.slice(-4)}</span>`, ibtn(s.reveal ? 'eye-slash' : 'eye', 'Show card number', 'reveal') + cp('number', 'card number'))
      + `<div class="fld"><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px"><div><span class="lb">Expires</span><span class="v num">${k.expiry}</span></div><div><span class="lb">Security code</span><span class="v pw">${s.reveal ? k.cvv : '•••'}</span></div><div><span class="lb">PIN</span><span class="v pw">${s.reveal ? k.pin : '••••'}</span></div></div></div>`;
  } else {
    if (e.username) h += fld(e.kind === 'wifi' ? 'Network name' : 'Username', esc(e.username), cp('username', 'username'));
    if (e.password) h += `<div class="fld"><div><span class="lb">${e.kind === 'wifi' ? 'Wi-Fi password' : 'Password'}</span><span class="v pw">${s.reveal ? pwHtml(e.password) : dots(e.password.length)}</span><div class="pwm num${c.level === 'bad' ? ' bad' : ''}">${c.word} · ${e.password.length} characters · about ${c.b} bits</div></div>${ibtn(s.reveal ? 'eye-slash' : 'eye', s.reveal ? 'Hide password' : 'Show password', 'reveal')}${cp('password', 'password')}</div>`;
    if (e.kind === 'wifi') h += fld('Security', 'WPA3 Personal', ibtn('qr-code', 'Show as QR code', 'dialog', 'wifiQr'));
    if (e.totp) h += `<div class="fld otp"><div><span class="lb">One-time code</span><span class="big num" data-totp="${e.totp}">${fmtCode(code(e.totp, step()))}</span><div class="bar"><i data-tick></i></div><div class="secs num" data-secs></div></div>${cp('code', 'one-time code')}</div>`;
    if (e.passkey) h += fld('Passkey', `${esc(e.passkey)} · ${esc(e.username)}`, `<span class="ibtn" style="cursor:default">${ic('fingerprint')}</span>`);
    if (e.kind === 'ssh') h += fld('SSH key · ED25519', '<span class="pw" style="font-size:13px">SHA256:3m5Jq1yZp8Xc0b7oV2kLr9sT4uWnE6dHfGa1iKoP+Qw</span>', cp('fingerprint', 'fingerprint'))
      + `<div class="fld"><div><span class="lb">SSH agent</span><span class="v" style="display:flex;gap:8px;align-items:center;margin-top:4px"><span class="pill pos">${icf('check-circle')}Loaded</span><span class="pwm" style="margin:0">Removed when the vault locks</span></span></div></div>`;
  }
  h += '</div><div class="panel">';
  h += fld('Group', g ? `<span style="display:inline-flex;gap:8px;align-items:center">${tile(g.c, g.icon)}${g.name}</span>` : 'Personal');
  if (e.url && e.kind !== 'login') h += fld('Address', esc(e.url));
  if (e.tags.length) h += fld('Tags', `<span class="chips">${e.tags.map((t) => `<span class="chip">#${esc(t)}</span>`).join('')}</span>`);
  if (e.files.length) h += fld('Attachments', e.files.map((f) => `<span class="file">${ic('paperclip')}${esc(f.name)} <small class="num">${f.size}</small></span>`).join(''));
  if (e.notes) h += fld('Notes', `<span class="v wrap">${esc(e.notes)}</span>`);
  h += `</div><div class="rfoot num"><span>Modified ${fmtDay(e.modified)}, ${fmtTime(e.modified)}</span>${e.hist ? `<button data-a="editpage" data-v="history">${plural(e.hist, 'earlier version', 'earlier versions')}</button>` : '<span>No earlier versions</span>'}</div>`;
  return h;
}
const fld = (label, value, tools = '') => `<div class="fld"><div><span class="lb">${label}</span><span class="v">${value}</span></div>${tools}</div>`;

function overlays(s) {
  const o = s.overlay; if (!o || o === 'tips') return '';
  if (o === 'more') return `<div class="menu" style="top:186px;right:20px">${[
    ['copy', 'Copy Username', '⌘B'], ['copy', 'Copy Password', '⌘C'], ['link', 'Copy URL', '⇧⌘U'], ['clock-countdown', 'Copy One-Time Code', '⌘T'], 0,
    ['keyboard', 'Type Login', '⇧⌘V'], ['arrow-square-out', 'Open URL', '⌘U'], ['qr-code', 'Show Code as QR', ''], 0,
    ['copy-simple', 'Clone Entry…', '⌘D', 'clone'], ['folder-simple', 'Move to Group ▸', ''], ['clock-counter-clockwise', 'History', ''], 0,
  ].map((m) => m ? `<button class="mi"${m[3] ? ` data-a="dialog" data-v="${m[3]}"` : ''}>${ic(m[0])}${m[1]}<span class="k">${m[2]}</span></button>` : '<div class="msep"></div>').join('')}<button class="mi neg" data-a="dialog" data-v="delete">${ic('trash')}Move to Recycle Bin<span class="k">⌘⌫</span></button></div>`;
  if (o === 'sort') return `<div class="menu" style="top:132px;right:22px;min-width:200px"><div class="mh">Sort by</div>${[['modified', 'Modified'], ['title', 'Title'], ['created', 'Created']].map(([k, l]) => `<button class="mi check" data-a="sort" data-v="${k}">${(s.sort || 'modified') === k ? ic('check') : '<span style="width:16px"></span>'}${l}</button>`).join('')}<div class="msep"></div><button class="mi check">${ic('check')}Newest first</button><button class="mi check"><span style="width:16px"></span>Oldest first</button></div>`;
  if (o === 'vault') return `<div class="menu" style="top:112px;left:12px;width:300px"><div class="mh">Open vaults</div>${VAULTS.map((v) => `<button class="mi${v.id === (s.vault || 'personal') ? ' on' : ''}">${tile(v.c, v.icon)}${v.name}<span class="k">${v.locked ? ic('lock-simple') : 'Open'}</span></button>`).join('')}<div class="msep"></div>
    <button class="mi" data-a="dialog" data-v="none">${ic('plus-circle')}New Vault…<span class="k">⇧⌘N</span></button><button class="mi">${ic('folder-open')}Open Vault…<span class="k">⌘O</span></button><button class="mi">${ic('download-simple')}Import…</button><div class="msep"></div>
    <button class="mi">${ic('sliders-horizontal')}Vault Settings…<span class="k">⇧⌘,</span></button><button class="mi">${ic('lock-simple')}Lock Personal<span class="k">⌘L</span></button><button class="mi">${ic('lock-key')}Lock Everything<span class="k">⇧⌘L</span></button></div>`;
  if (o === 'gen') return `<div class="floatp" style="top:118px;right:166px">${generator(s)}</div>`;
  return '';
}

function lockedWindow(s) {
  const v = vaultOf(s), pw = s.unlock === 'password';
  const body = pw ? `<form class="stack" onsubmit="return false">
      <div><label class="lab" for="upw">Password</label><div class="inp lg${s.err ? ' bad' : ''}">${ic('key')}<input id="upw" type="password" value="${s.err ? 'hunter2hunter2' : ''}" placeholder="Vault password" autocomplete="current-password">${ibtn('eye', 'Show password')}</div>
      ${s.err ? `<div class="uerr" style="margin-top:8px">${ic('warning-circle')}<span>Wrong password, key file or security key. Check them and try again.</span></div>` : ''}</div>
      <div class="extra"><div>${ic('file-lock')}<span class="grow">Key file<small>${s.err ? 'personal.larsalkey · ~/Documents/Keys' : 'None'}</small></span><button class="btn sm">${s.err ? 'Change…' : 'Choose…'}</button></div>
        <div>${brandSvg('yubico', 16)}<span class="grow">Security key<small>${s.err ? 'YubiKey 5 NFC · serial 24531878 · slot 2' : 'Not used'}</small></span>${sw(!!s.err, 'Use a security key')}</div></div>
      <button class="btn primary xl wide" data-a="unlock">Unlock</button>
      <div class="opts"><button data-a="unlockmode" data-v="touch">${ic('fingerprint')}Use Touch ID</button></div></form>`
    : `<button class="touch" data-a="unlock" aria-label="Unlock with Touch ID">${ic('fingerprint')}</button>
      <p style="margin:14px 0 0;color:var(--muted)">Touch ID or enter your Mac password to unlock</p>
      <div class="stack" style="margin-top:28px"><button class="btn xl wide" data-a="unlockmode" data-v="password">${ic('key')}Use vault password instead</button></div>`;
  return `<div style="display:flex;flex-direction:column;height:100%">
    <div style="height:52px;display:flex;align-items:center;gap:16px;padding:0 12px 0 18px"><div class="lights"><i></i><i></i><i></i></div>
      <button class="btn ghost" data-a="menu" data-v="vault" style="margin-left:96px">${tile(v.c, v.icon)}<b style="font-weight:600">${v.name}</b>${ic('caret-up-down')}</button></div>
    <main class="sheet" style="margin-left:8px;flex:1"><div class="lock"><div class="ucard">${tile(v.c, v.icon, 'xl')}<h1>${v.name} is locked</h1><div class="path">${v.path}</div>${body}</div></div>
      <div class="lockfoot num"><span>Locked at 10:12 after 5 minutes without use</span><span>Other vaults: Work ${ic('lock-simple')} · Family ${ic('lock-simple')}</span></div></main></div>
    ${s.overlay === 'vault' ? overlays({ ...s, overlay: 'vault' }).replace('top:112px;left:12px', 'top:48px;left:140px') : ''}`;
}

function emptyVault() {
  return `<div class="trow"><div><h1>All entries</h1><p class="sub">Family.larsalvault · created just now</p></div><div class="acts"><button class="btn lg primary">${ic('plus')}New Entry</button></div></div>
    <div style="flex:1;display:grid;place-items:center"><div style="width:520px;text-align:center"><div style="display:flex;justify-content:center">${tile('--pink', 'users-three', 'xl')}</div>
      <h2 style="margin:18px 0 6px;font-size:20px;font-weight:600">Family is ready</h2><p style="margin:0 0 24px;color:var(--muted)">The vault is saved and encrypted. Add your first entry, or bring passwords over from another app.</p>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;text-align:left">${[['plus', '--blue', 'New entry', 'A login, card or note'], ['download-simple', '--green', 'Import', 'CSV and other managers'], ['folder-simple', '--orange', 'New group', 'Sort entries like folders']].map(([i, c, t, d]) => `<button class="opt" style="text-align:left">${tile(c, i, 'md')}<h4>${t}</h4><p style="margin:0">${d}</p></button>`).join('')}</div></div></div>`;
}

// ---------- entry editor ----------
const ED_PAGES = [['entry', 'key', 'Entry'], ['advanced', 'list-bullets', 'Advanced'], ['icon', 'image-square', 'Icon'], ['autotype', 'keyboard', 'Auto-Type'], ['browser', 'globe-simple', 'Browser'], ['ssh', 'terminal-window', 'SSH Agent'], ['props', 'info', 'Properties'], ['history', 'clock-counter-clockwise', 'History']];
function editorView(s) {
  const e = byId(s.edit || 'github'), isNew = s.isNew, page = s.page || 'entry';
  const nav = ED_PAGES.map(([id, icon, label]) => `<button class="si" data-a="page" data-v="${id}"${page === id ? ' aria-current="page"' : ''}>${ic(icon)}<span class="lbl">${label}</span>${id === 'history' && !isNew ? `<span class="cnt num">${e.hist}</span>` : id === 'advanced' && !isNew ? `<span class="cnt num">${e.files.length + (e.id === 'github' ? 3 : 0)}</span>` : ''}</button>`).join('');
  return `<div class="trow">${isNew ? `<span class="logo lg letter" style="--h:200">${ic('plus')}</span>` : logo(e, 'lg')}<div><h1>${isNew ? 'New entry' : 'Edit entry'}</h1><p class="sub">${isNew ? 'In Work · Personal' : `${esc(e.title)} · ${groupOf(e.group) ? groupOf(e.group).name : 'Personal'}`}</p></div>
      <div class="acts"><button class="btn lg" data-a="cancel">Cancel</button><button class="btn lg primary" data-a="save">Save ${kbd('⌘S')}</button></div></div>
    <div class="ed"><nav class="ednav" aria-label="Editor pages">${nav}</nav><div class="edbody">${EDP[page](e, s)}</div></div>`;
}
const fieldRow = (label, inner, help = '', span = false) => `<div${span ? ' class="span"' : ''}><label class="lab">${label}</label>${inner}${help ? `<div class="help">${help}</div>` : ''}</div>`;
const inp = (value, opts = {}) => `<div class="inp${opts.cls ? ' ' + opts.cls : ''}">${opts.lead ? ic(opts.lead) : ''}<input value="${esc(value)}" placeholder="${esc(opts.ph || '')}"${opts.mono ? ' class="mono"' : ''} spellcheck="false" autocomplete="off">${opts.tools || ''}</div>`;
const EDP = {
  entry(e, s) {
    const n = s.isNew, pw = n ? 'k7#Rv2!pXq9@Lw4$Tz8m' : e.password, c = n ? { word: 'Strong', b: 131 } : check(e);
    return `<section class="edsec"><h3>Sign-in</h3><div class="fgrid">
      ${fieldRow('Title', inp(n ? '' : e.title, { ph: 'GitHub, Bank, Home Wi-Fi…' }), '', true)}
      ${fieldRow('Username', inp(n ? '' : e.username, { ph: 'name@example…', lead: 'user' }))}
      <div><label class="lab">Password <small>· ${c.word}, about ${c.b} bits</small></label><div class="inp"><span class="pw">${s.reveal ? pwHtml(pw) : pwHtml(pw)}</span>${ibtn('eye-slash', 'Hide password', '', '', 'sm')}${ibtn('password', 'Open generator (⌥⌘G)', 'menu', 'gen', 'sm')}</div><div class="bar" style="height:3px;margin-top:8px"><i style="width:${Math.min(100, c.b / 1.28)}%;background:var(--positive)"></i></div></div>
      ${fieldRow('Website', inp(n ? '' : e.url, { ph: 'https://…', lead: 'globe-simple', tools: n ? '' : ibtn('arrow-square-out', 'Open website', '', '', 'sm') }), n ? '' : '<button class="link">+ Add another website</button> · gist.github.com is also allowed', true)}
    </div></section>
    <section class="edsec"><h3>Two-step sign-in</h3><div class="panel" style="padding:0">
      ${n ? `<div class="fld"><div><span class="v">One-time code</span><span class="lb">Paste the secret key a website shows when you turn on two-step sign-in.</span></div><button class="btn" data-a="dialog" data-v="totpSetup">${ic('plus')}Add one-time code…</button></div>`
        : `<div class="fld"><div><span class="lb">One-time code · 6 digits every 30 s</span><span class="v code num" data-totp="${e.totp}" style="font-size:18px">${fmtCode(code(e.totp, step()))}</span></div><button class="btn sm" data-a="dialog" data-v="totpQr">${ic('qr-code')}Show QR</button><button class="btn sm" data-a="dialog" data-v="totpSetup">Change…</button></div>
        <div class="fld"><div><span class="lb">Passkey</span><span class="v">${e.passkey} · ${e.username} · added Oct 22</span></div><button class="btn sm" data-a="dialog" data-v="passkeyRemove" style="color:var(--negative)">Remove</button></div>`}</div></section>
    <section class="edsec"><h3>Organize</h3><div class="fgrid">
      ${fieldRow('Group', `<div class="inp">${tile('--brown', 'briefcase')}<span style="flex:1">Work</span>${ic('caret-up-down')}</div>`)}
      ${fieldRow('Tags', `<div class="inp" style="gap:6px">${(n ? [] : e.tags).map((t) => `<span class="chip">#${t}<span class="x">${ic('x')}</span></span>`).join('')}<input placeholder="Add a tag…"></div>`)}
      <div class="span"><label class="lab">Expires</label><div class="inline">${sw(false, 'Expires')}<div class="inp off" style="max-width:200px">${ic('calendar-blank')}<input placeholder="Never" disabled></div><button class="btn" disabled style="opacity:.55">In 3 months ${ic('caret-down')}</button></div></div>
    </div></section>
    <section class="edsec"><h3>Notes</h3><textarea class="ta" placeholder="Anything you want to keep with this entry">${n ? '' : esc(e.notes)}</textarea></section>`;
  },
  advanced(e) {
    const rowsF = [['Recovery email', 'alex.backup@posteo.de', false], ['Organization', 'morgan-labs', false], ['API token', 'ghp_••••••••••••••••••••', true]];
    return `<section class="edsec"><h3>Custom fields</h3><p class="lead">Extra values kept with the entry. Protected values stay hidden and encrypted in memory.</p>
      <div class="panel tbl-p"><table class="mini"><thead><tr><th>Name</th><th>Value</th><th>Protected</th><th></th></tr></thead><tbody>
      ${rowsF.map(([k, v, p]) => `<tr><td style="width:30%"><b style="font-weight:500">${k}</b></td><td class="${p ? 'mono' : ''}">${v}</td><td>${sw(p, 'Protect ' + k)}</td><td class="act">${ibtn('copy', 'Copy', '', '', 'sm')}${ibtn('trash', 'Remove field', '', '', 'sm')}</td></tr>`).join('')}
      </tbody></table></div><button class="btn" style="margin-top:12px">${ic('plus')}Add field</button></section>
    <section class="edsec"><h3>Attachments</h3><div class="panel tbl-p"><table class="mini"><thead><tr><th>File</th><th class="r">Size</th><th></th></tr></thead><tbody>
      ${e.files.map((f) => `<tr><td>${ic('file-text')} ${esc(f.name)}</td><td class="r num">${f.size}</td><td class="act"><button class="btn sm">Open</button> <button class="btn sm">Save…</button> ${ibtn('trash', 'Remove', '', '', 'sm')}</td></tr>`).join('')}
      </tbody></table></div>
      <div class="empty" style="margin-top:12px;text-align:center">${ic('upload-simple')} Drop files here, or <button class="link">choose files…</button> · up to 10 MB each</div></section>`;
  },
  icon(e) {
    const std = ['key', 'lock-simple', 'globe-simple', 'envelope-simple', 'bank', 'credit-card', 'shopping-bag', 'briefcase', 'house-line', 'wifi-high', 'hard-drives', 'terminal-window', 'database', 'cloud', 'device-mobile', 'desktop', 'game-controller', 'film-strip', 'music-notes', 'airplane', 'car', 'heart', 'student', 'certificate', 'identification-card', 'shield-check', 'users-three', 'chat-circle', 'printer', 'star'];
    return `<section class="edsec"><h3>Icon</h3><p class="lead">The icon shows in the list and the sidebar.</p>
      <div class="choices">
        <button class="choice" aria-checked="true">${rb(true)}<span style="flex:1"><b>Website logo</b><small>The ${esc(e.title)} logo, stored in the vault. Fetched once from the logo set that ships with Larsal: nothing is downloaded.</small></span>${logo(e, 'lg')}</button>
        <button class="choice" aria-checked="false">${rb(false)}<span style="flex:1"><b>Symbol and colour</b><small>Pick one below.</small></span></button>
        <button class="choice" aria-checked="false">${rb(false)}<span style="flex:1"><b>The group's icon</b><small>Follows the Work group.</small></span>${tile('--brown', 'briefcase', 'lg')}</button></div></section>
    <section class="edsec"><h3>Symbols</h3><div class="panel"><div class="icongrid">${std.map((n, i) => `<button aria-pressed="${i === 0}" aria-label="${n}">${ic(n)}</button>`).join('')}</div>
      <div style="display:flex;align-items:center;gap:16px;margin-top:16px"><span class="lab" style="margin:0">Colour</span><div class="swatches">${['--blue', '--teal', '--green', '--orange', '--pink', '--red', '--purple', '--brown', '--slate', '--gray'].map((c, i) => `<button style="--c:var(${c})" aria-pressed="${i === 1}" aria-label="${c.slice(2)}"></button>`).join('')}</div></div></div></section>`;
  },
  autotype() {
    return `<section class="edsec"><div class="panel" style="padding:0"><div class="srow"><div><span class="t">Auto-Type for this entry</span><span class="d">Types the sign-in into the window in front when you press ⌃⌥V.</span></div>${sw(true, 'Auto-Type')}</div></div></section>
    <section class="edsec"><h3>Sequence</h3><div class="choices">
      <button class="choice" aria-checked="false">${rb(false)}<span><b>Use the group's sequence</b><small class="mono">{USERNAME}{TAB}{PASSWORD}{ENTER}</small></span></button>
      <button class="choice" aria-checked="true">${rb(true)}<span style="flex:1"><b>Custom sequence</b>${inp('{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}', { mono: true })}<small style="margin-top:6px">Placeholders: {USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 500}</small></span></button></div></section>
    <section class="edsec"><h3>Windows</h3><p class="lead">Auto-Type also offers this entry in windows whose title matches.</p><div class="panel tbl-p"><table class="mini"><thead><tr><th>Window title</th><th>Sequence</th><th></th></tr></thead><tbody>
      <tr><td class="mono">*GitHub*</td><td class="dash">Entry sequence</td><td class="act">${ibtn('trash', 'Remove', '', '', 'sm')}</td></tr>
      <tr><td class="mono">Sign in to GitHub · GitHub — Safari</td><td class="mono" style="font-size:12px">{USERNAME}{TAB}{PASSWORD}{ENTER}</td><td class="act">${ibtn('trash', 'Remove', '', '', 'sm')}</td></tr></tbody></table></div>
      <button class="btn" style="margin-top:12px">${ic('plus')}Add window</button></section>`;
  },
  browser(e) {
    return `<section class="edsec"><h3>Sites</h3><p class="lead">The browser extension fills this entry on its website and on these sites.</p><div class="fgrid">
      ${fieldRow('Also allowed on', `<div class="inp" style="gap:6px">${(e.allow || []).map((t) => `<span class="chip">${t}<span class="x">${ic('x')}</span></span>`).join('')}<input placeholder="Add a site…"></div>`)}
      ${fieldRow('Never on', `<div class="inp"><input placeholder="Add a site…"></div>`)}</div></section>
    <section class="edsec"><h3>Options</h3><div class="grp"><div class="box">
      <div class="srow"><div><span class="t">Hide this entry from the browser</span><span class="d">The extension never sees it.</span></div>${sw(false, 'Hide from browser')}</div>
      <div class="srow"><div><span class="t">Fill, but do not submit</span><span class="d">You press the sign-in button yourself.</span></div>${sw(true, 'Do not submit')}</div>
      <div class="srow"><div><span class="t">Only for sign-in pop-ups (HTTP)</span><span class="d">For routers and old intranet pages.</span></div>${sw(false, 'HTTP only')}</div></div></div></section>
    <section class="edsec"><h3>Browsers that used this entry</h3><div class="panel tbl-p"><table class="mini"><tbody>
      <tr><td style="display:flex;gap:10px;align-items:center">${brandSvg('firefoxbrowser', 18)} Firefox on MacBook</td><td class="r num dash">Today, 09:12</td></tr>
      <tr><td style="display:flex;gap:10px;align-items:center">${brandSvg('safari', 18)} Safari</td><td class="r num dash">Oct 20</td></tr></tbody></table></div></section>`;
  },
  ssh() {
    const w = byId('web01');
    return `<section class="edsec"><div class="panel" style="padding:0"><div class="srow"><div><span class="t">Use this entry's key with the SSH agent</span><span class="d">${esc(w.title)} · the entry's password unlocks the key</span></div>${sw(true, 'SSH agent')}</div></div></section>
    <section class="edsec"><h3>Private key</h3><div class="choices">
      <button class="choice" aria-checked="true">${rb(true)}<span style="flex:1"><b>From an attachment</b><span class="selx" style="margin-top:8px">${ic('paperclip')} id_ed25519 · 464 B ${ic('caret-up-down')}</span></span></button>
      <button class="choice" aria-checked="false">${rb(false)}<span style="flex:1"><b>From a file on this Mac</b><small class="mono">~/.ssh/id_ed25519</small></span></button></div>
      <div class="panel" style="padding:16px;margin-top:12px"><dl class="kv"><dt>Type</dt><dd>ED25519</dd><dt>Fingerprint</dt><dd class="mono">SHA256:3m5Jq1yZp8Xc0b7oV2kLr9sT4uWnE6dHfGa1iKoP+Qw</dd><dt>Comment</dt><dd>alex@macbook</dd><dt>Public key</dt><dd><div class="keybox">ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH8d2c4Q0mVq7kLr9sT4uWnE6dHfGa1iKoPzX3bYc alex@macbook</div><button class="btn sm" style="margin-top:8px">${ic('copy')}Copy public key</button></dd></dl></div></section>
    <section class="edsec"><h3>Agent</h3><div class="grp"><div class="box">
      <div class="srow"><div><span class="t">Add the key when the vault unlocks</span></div>${sw(true, 'Add on unlock')}</div>
      <div class="srow"><div><span class="t">Remove the key when the vault locks</span></div>${sw(true, 'Remove on lock')}</div>
      <div class="srow"><div><span class="t">Ask before each use</span><span class="d">Larsal shows a question every time a program wants to sign with the key.</span></div>${sw(false, 'Confirm')}</div>
      <div class="srow"><div><span class="t">Remove the key after</span></div><div class="ctl">${stepper(10, 'min')}${sw(false, 'Lifetime')}</div></div></div></div>
      <div class="inline" style="margin-top:12px"><button class="btn">${ic('plus-circle')}Add to agent now</button><button class="btn">${ic('minus-circle')}Remove from agent</button><span class="pill pos">${icf('check-circle')}Loaded in agent</span></div></section>`;
  },
  props(e) {
    return `<section class="edsec"><h3>Properties</h3><div class="panel" style="padding:18px"><dl class="kv">
      <dt>Identifier</dt><dd class="mono">3f2a9c1e-77b4-4c0d-9a51-6e0b2d8c4f17</dd><dt>Created</dt><dd class="num">${fmtDate(e.created)}, ${fmtTime(e.created)}</dd><dt>Modified</dt><dd class="num">${fmtDate(e.modified)}, ${fmtTime(e.modified)}</dd>
      <dt>Last used</dt><dd class="num">Today, 09:12</dd><dt>Expires</dt><dd>Never</dd><dt>Times used</dt><dd class="num">214</dd><dt>History</dt><dd class="num">${plural(e.hist, 'version', 'versions')} · 4.8 KB</dd></dl></div></section>
    <section class="edsec"><h3>Custom data</h3><p class="lead">Values other apps and the browser extension store with this entry.</p><div class="panel tbl-p"><table class="mini"><thead><tr><th>Key</th><th>Value</th><th></th></tr></thead><tbody>
      <tr><td class="mono">browser.last_fill</td><td class="num">2026-10-27 09:12</td><td class="act">${ibtn('trash', 'Remove', '', '', 'sm')}</td></tr></tbody></table></div></section>`;
  },
  history(e) {
    return `<section class="edsec"><h3>Earlier versions</h3><p class="lead">Larsal keeps the last 10 versions of each entry, up to 6 MB per vault.</p><div class="panel tbl-p"><table class="mini"><thead><tr><th>Saved</th><th>Change</th><th>Password</th><th></th></tr></thead><tbody>
      ${HISTORY.map((h) => `<tr><td class="num">${fmtDate(h.when)}, ${fmtTime(h.when)}</td><td>${h.what}</td><td>${h.pw ? '<span class="pill neu">changed</span>' : '<span class="dash">same</span>'}</td><td class="act"><button class="btn sm" data-a="dialog" data-v="histShow">Show</button> <button class="btn sm">Restore</button> ${ibtn('trash', 'Delete version', '', '', 'sm')}</td></tr>`).join('')}
      </tbody></table></div><button class="btn" style="margin-top:12px;color:var(--negative)">${ic('trash')}Delete all history</button></section>`;
  },
};

// ---------- generator ----------
function rnd(seed) { let h = seed >>> 0; return () => { h = (Math.imul(h ^ (h >>> 15), 2246822507) + 0x9e3779b9) >>> 0; return h / 4294967296; }; }
function generate(s) {
  const r = rnd(1234 + (s.seed || 0) * 977 + (s.glen || 20) * 13);
  if (s.gmode === 'phrase') return Array.from({ length: s.gwords || 5 }, () => WORDS[Math.floor(r() * WORDS.length)]).join('-');
  const sets = s.gsets || { upper: true, lower: true, digits: true, symbols: true };
  const pool = (sets.upper ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : '') + (sets.lower ? 'abcdefghijkmnopqrstuvwxyz' : '') + (sets.digits ? '23456789' : '') + (sets.symbols ? '!@#$%&*+-=?' : '');
  return Array.from({ length: s.glen || 20 }, () => pool[Math.floor(r() * pool.length)]).join('');
}
function generator(s) {
  const phrase = s.gmode === 'phrase', pw = generate(s);
  const b = phrase ? Math.round((s.gwords || 5) * 12.9) : Math.round((s.glen || 20) * Math.log2(78));
  const sets = s.gsets || { upper: true, lower: true, digits: true, symbols: true };
  return `<div class="gen" role="dialog" aria-label="Password generator"><div class="gh"><b>Generator</b><span class="segc"><button data-a="gmode" data-v="pw" aria-pressed="${!phrase}">Password</button><button data-a="gmode" data-v="phrase" aria-pressed="${phrase}">Passphrase</button></span></div>
    <div class="out"><span class="pw">${pwHtml(pw)}</span>${ibtn('arrows-clockwise', 'New password', 'regen')}${ibtn('copy', 'Copy', 'copy', 'generated')}</div>
    <div class="str num"><span style="color:var(--positive);font-weight:500">${b >= 100 ? 'Excellent' : 'Strong'}</span><span class="bar"><i style="width:${Math.min(100, b / 1.3)}%"></i></span><span>${b} bits</span></div>
    ${phrase ? `<div class="row2"><label>Words</label><input class="range" type="range" min="3" max="10" value="${s.gwords || 5}" data-a="gwords"><span class="val num">${s.gwords || 5}</span></div>
      <div class="row2"><label>Separator</label><span class="segc">${['-', '.', 'space', '_'].map((x, i) => `<button aria-pressed="${i === 0}" class="mono">${x}</button>`).join('')}</span></div>
      <div class="row2"><label>Case</label><span class="segc"><button aria-pressed="true">lower</button><button>Title</button><button>UPPER</button></span></div>`
    : `<div class="row2"><label>Length</label><input class="range" type="range" min="8" max="64" value="${s.glen || 20}" data-a="glen"><span class="val num">${s.glen || 20}</span></div>
      <div class="sets">${[['upper', 'A–Z'], ['lower', 'a–z'], ['digits', '0–9'], ['symbols', '!@#$']].map(([k, l]) => `<button aria-pressed="${!!sets[k]}" data-a="gset" data-v="${k}">${l}</button>`).join('')}<button aria-pressed="false">Äéß</button></div>
      <button class="chkrow" style="margin-top:12px">${cb(true)}<span>Leave out look-alikes <span class="mono" style="color:var(--muted)">l I 1 O 0</span></span></button>`}
    <div class="gf"><button class="btn" data-a="copy" data-v="generated">${ic('copy')}Copy</button>${s.ext ? `<button class="btn primary">${ic('key-return')}Fill on page</button>` : s.mode === 'editor' ? `<button class="btn primary">Use password</button>` : `<button class="btn primary" data-a="new">${ic('plus')}New entry with it</button>`}</div></div>`;
}

// ---------- reports ----------
const REP = [['health', 'Health check'], ['breach', 'Breach check'], ['stats', 'Statistics'], ['passkeys', 'Passkeys'], ['browser', 'Browser']];
function reportsView(s) {
  const r = s.rep || 'health';
  return `<div class="trow"><div><h1>Reports</h1><p class="sub num">Personal · ${live.length} entries checked at 10:30</p></div><div class="acts"><button class="btn lg">${ic('arrows-clockwise')}Check again</button></div></div>
    <div class="tabsrow"><div class="tabs" role="tablist">${REP.map(([id, l]) => `<button class="tab" role="tab" data-a="rep" data-v="${id}" aria-selected="${r === id}">${l}${id === 'health' ? `<span class="n num alert">${attention().length}</span>` : ''}</button>`).join('')}</div></div>
    <div class="rep">${REPS[r](s)}</div>`;
}
const entryCell = (e, sub) => `<span class="idc">${logo(e, 'xs')}<span><b>${esc(e.title)}</b><small>${sub}</small></span></span>`;
const REPS = {
  health() {
    const a = attention(), by = (k) => a.filter((e) => check(e).issue === k).length;
    const order = { Reused: 0, Weak: 1, Expired: 2 };
    return `<div class="kpis num"><div><span>Need attention</span><b class="bad">${a.length}</b><small>of ${live.filter((e) => e.password).length} passwords</small></div><div><span>Reused</span><b>${by('Reused')}</b><small>1 password, 2 entries</small></div><div><span>Weak</span><b>${by('Weak')}</b><small>under 40 bits</small></div><div><span>Expired</span><b>${by('Expired')}</b><small>past their date</small></div></div>
    <table class="rtbl"><thead><tr><th>Entry</th><th>Problem</th><th>Strength</th><th class="r">Changed</th><th></th></tr></thead><tbody>
    ${[...a].sort((x, y) => order[check(x).issue] - order[check(y).issue]).map((e) => { const c = check(e); return `<tr><td>${entryCell(e, esc(e.username))}</td><td><span class="pill ${c.level === 'warn' ? 'warn' : 'neg'}">${c.issue}</span> <span style="color:var(--muted);font-size:13px">${c.why}</span></td><td><span class="hl ${c.level}">${c.b} bits${meter(c.seg)}</span></td><td class="r num mod">${fmtMod(e.modified)}</td><td class="act"><button class="btn sm">Change password</button> ${ibtn('dots-three', 'More', '', '', 'sm')}</td></tr>`; }).join('')}
    </tbody></table><p style="color:var(--muted);font-size:13px;margin:16px 10px 0">${live.filter((e) => e.password).length - a.length} other passwords are strong, unique and current. Entries you exclude are listed under the ⋯ menu.</p>`;
  },
  breach() {
    const hits = [['amazon', 18442], ['ebay', 18442], ['router', 214876], ['reddit', 3107]];
    return `<div class="notice neu" style="margin:0 0 20px">${ic('shield-check')}<div><b>Checked online at 10:28.</b> Larsal sent only the first 5 characters of each password's SHA-1 hash. The service never saw a password or a username. <div class="acts"><button>Check with a downloaded list instead</button><button>Turn off</button></div></div></div>
    <div class="kpis num" style="grid-template-columns:repeat(3,1fr)"><div><span>Found in breaches</span><b class="bad">${hits.length}</b><small>passwords</small></div><div><span>Not found</span><b>${live.filter((e) => e.password).length - hits.length}</b><small>passwords</small></div><div><span>Largest count</span><b>214,876</b><small>times seen</small></div></div>
    <table class="rtbl"><thead><tr><th>Entry</th><th class="r">Seen in breaches</th><th>What to do</th><th></th></tr></thead><tbody>
    ${hits.sort((a, b) => b[1] - a[1]).map(([id, n]) => { const e = byId(id); return `<tr><td>${entryCell(e, esc(e.username))}</td><td class="r num"><b style="font-weight:500;color:var(--negative)">${n.toLocaleString('en-US')}</b> times</td><td style="color:var(--muted);font-size:13px">Attackers try this password first. Change it on ${esc(host(e.url))}.</td><td class="act"><button class="btn sm">Change password</button></td></tr>`; }).join('')}</tbody></table>`;
  },
  stats() {
    const pws = live.filter((e) => e.password), lens = pws.map((e) => e.password.length), avg = (lens.reduce((a, b) => a + b, 0) / lens.length).toFixed(1);
    const bucket = [['8–11', (n) => n < 12], ['12–15', (n) => n >= 12 && n < 16], ['16–19', (n) => n >= 16 && n < 20], ['20 and more', (n) => n >= 20]].map(([l, f]) => [l, lens.filter(f).length]);
    const max = Math.max(...bucket.map((b) => b[1]));
    const age = (d) => (NOW - new Date(d)) / 864e5;
    const ages = [['This month', (e) => age(e.modified) < 31], ['1–6 months', (e) => age(e.modified) >= 31 && age(e.modified) < 183], ['Older', (e) => age(e.modified) >= 183]].map(([l, f]) => [l, pws.filter(f).length]);
    const amax = Math.max(...ages.map((b) => b[1]));
    return `<div class="twocol"><div class="statlist num">${[['File', 'Personal.larsalvault'], ['Size', '84 KB'], ['Format', 'Version 4.1'], ['Encryption', 'AES-256 · Argon2id, 64 MiB, 1 s'], ['Entries', live.length + ' (' + bin.length + ' in the Recycle Bin)'], ['Groups', GROUPS.length], ['Attachments', '4 · 2.3 KB'], ['Unique passwords', new Set(pws.map((e) => e.password)).size + ' of ' + pws.length], ['Average length', avg + ' characters'], ['Last saved', 'Today, 08:50']].map(([k, v]) => `<div><span>${k}</span><b style="font-weight:500">${v}</b></div>`).join('')}</div>
      <div><h3 style="margin:0 0 14px;font-size:15px;font-weight:600">Password length</h3><div class="hbar num">${bucket.map(([l, n]) => `<div><span>${l}</span><i style="width:${(n / max) * 100}%"></i><span class="r">${n}</span></div>`).join('')}</div>
      <h3 style="margin:28px 0 14px;font-size:15px;font-weight:600">Last changed</h3><div class="hbar num">${ages.map(([l, n]) => `<div><span>${l}</span><i style="width:${(n / amax) * 100}%;background:var(--muted);opacity:.5"></i><span class="r">${n}</span></div>`).join('')}</div></div></div>`;
  },
  passkeys() {
    const p = live.filter((e) => e.passkey);
    return `<table class="rtbl" style="margin-top:0"><thead><tr><th>Site</th><th>User</th><th>Entry also has</th><th class="r">Added</th><th></th></tr></thead><tbody>
      ${p.map((e) => `<tr><td>${entryCell(e, esc(e.passkey))}</td><td>${esc(e.username)}</td><td>${e.password ? '<span class="pill neu">password</span> ' : ''}${e.totp ? '<span class="pill neu">one-time code</span>' : ''}${!e.password && !e.totp ? '<span class="dash">passkey only</span>' : ''}</td><td class="r num mod">${fmtDay(e.modified)}</td><td class="act"><button class="btn sm" data-a="dialog" data-v="passkeyRemove">Remove</button></td></tr>`).join('')}</tbody></table>`;
  },
  browser() {
    const p = live.filter((e) => e.allow || e.deny);
    return `<table class="rtbl" style="margin-top:0"><thead><tr><th>Entry</th><th>Also allowed on</th><th>Never on</th><th>Options</th></tr></thead><tbody>
      ${p.map((e) => `<tr><td>${entryCell(e, esc(host(e.url)))}</td><td>${(e.allow || []).map((x) => `<span class="chip">${x}</span>`).join(' ') || '<span class="dash">—</span>'}</td><td>${(e.deny || []).map((x) => `<span class="chip">${x}</span>`).join(' ') || '<span class="dash">—</span>'}</td><td>${e.id === 'github' ? '<span class="pill neu">fill, no submit</span>' : '<span class="dash">—</span>'}</td></tr>`).join('')}</tbody></table>
      <p style="color:var(--muted);font-size:13px;margin:16px 10px 0">Connected browsers: Firefox on MacBook (since Oct 12) · Safari (since Sep 3). Manage them in Vault Settings.</p>`;
  },
};

// ---------- settings windows ----------
const SETTINGS = [['general', 'General', '--gray', 'gear-six'], ['security', 'Security', '--blue', 'lock-key'], ['autotype', 'Auto-Type', '--orange', 'keyboard'], ['browser', 'Browser Integration', '--teal', 'globe-simple'], ['ssh', 'SSH Agent', '--graphite', 'terminal-window'], ['share', 'Shared Groups', '--green', 'share-network'], ['keys', 'Shortcuts', '--purple', 'command']];
const row = (t, d, ctl, cls = '') => `<div class="srow ${cls}"><div><span class="t">${t}</span>${d ? `<span class="d">${d}</span>` : ''}</div><div class="ctl">${ctl}</div></div>`;
const grp = (h, rowsH) => `<div class="grp">${h ? `<h4>${h}</h4>` : ''}<div class="box">${rowsH}</div></div>`;
const SETP = {
  general: () => grp('Startup', row('Open Larsal at login', '', sw(false, 'Login')) + row('Reopen the last vaults at start', '', sw(true, 'Reopen')) + row('Remember recent vaults', 'Also remembers which key file each one used.', stepper(10) + sw(true, 'Recent')) + row('Show entries that expire soon after unlocking', '', selx('Within 7 days') + sw(true, 'Expiry')) + row('Check for updates', 'Asks GitHub once a day. Nothing else leaves this Mac.', sw(true, 'Updates')) + row('Include beta versions', '', sw(false, 'Beta'), 'sub'))
    + grp('Saving', row('Save after every change', '', sw(true, 'Autosave')) + row('Save when locking', '', sw(true, 'Save on lock')) + row('Reload the vault when another app changes it', 'Merges your unsaved changes first.', sw(true, 'Reload')) + row('Keep a backup before saving', '<span class="mono">{DB_FILENAME}.old.larsalvault</span>', sw(true, 'Backup')) + row('Safe saving', 'Writes a temporary file, then replaces the vault in one step.', selx('Through a temporary file')))
    + grp('Entries', row('Ask before moving to the Recycle Bin', '', sw(true, 'Confirm')) + row('Make a password for every new entry', '', sw(true, 'Autogen')) + row('Double-clicking a row copies', '', selx('Password')) + row('Hide Larsal after copying', '', selx('Minimize') + sw(false, 'Hide')))
    + grp('Look', row('Appearance', '', `<span class="segc"><button aria-pressed="true">System</button><button>Light</button><button>Dark</button></span>`) + row('Colour digits and symbols in passwords', `<span class="pw" style="font-size:12px">${pwHtml('x9!Lq#4vT')}</span>`, sw(true, 'Colour')) + row('Monospace font in notes', '', sw(false, 'Mono notes')) + row('Show Larsal in the menu bar', '', selx('Monochrome icon') + sw(true, 'Menu bar')) + row('Closing the window keeps Larsal running', '', sw(true, 'Hide on close'))),
  security: () => grp('Timeouts', row('Clear the clipboard after', 'Copied passwords and codes disappear from the clipboard.', stepper(30, 's') + sw(true, 'Clipboard')) + row('Lock after no use for', '', stepper(5, 'min') + sw(true, 'Idle lock')) + row('Clear the search after', '', stepper(5, 'min') + sw(false, 'Clear search')))
    + grp('Locking', row('Unlock with Touch ID', 'Your vault key stays in the Secure Enclave keychain until Larsal quits or 8 hours pass.', sw(true, 'Touch ID')) + row('Lock when the screen locks', '', sw(true, 'Screen lock')) + row('Lock when you switch user', '', sw(true, 'User switch')) + row('Lock when the window is minimized', '', sw(false, 'Minimize')))
    + grp('Showing secrets', row('Hide passwords in the editor', '', sw(false, 'Editor')) + row('Hide passwords in the detail pane', '', sw(true, 'Preview')) + row('Hide one-time codes in the detail pane', '', sw(false, 'Codes')) + row('Hide notes', '', sw(false, 'Notes')) + row('Show dots for empty passwords', '', sw(false, 'Dots')))
    + grp('Privacy', row('Let other apps record Larsal\'s windows', 'Screen sharing and screenshots show Larsal as a blank window while this is off.', sw(false, 'Capture'))),
  autotype: () => `<div class="notice neu" style="margin:0 0 20px">${ic('check-circle')}<div><b>Accessibility access is on.</b> macOS lets Larsal type into other apps. <button class="link">Open Privacy & Security</button></div></div>`
    + grp('Shortcut', row('Type the login for the window in front', '', `<span class="kbd" style="font-size:13px;height:26px;line-height:26px;padding:0 10px">⌃⌥V</span><button class="btn sm">Change</button>`))
    + grp('Matching', row('Match by window title', '', sw(true, 'Title')) + row('Match by website address in the title', '', sw(true, 'URL')) + row('Always ask which entry to type', '', sw(false, 'Ask')) + row('Skip expired entries', '', sw(true, 'Expired')) + row('Lock again after typing', '', sw(false, 'Relock')))
    + grp('Timing', row('Wait before typing', '', stepper(500, 'ms')) + row('Pause between keys', '', stepper(25, 'ms')) + row('Do not type the same login again within', '', stepper(15, 's'))),
  browser: () => grp('', row('Let browsers use Larsal', 'Fill sign-ins, one-time codes and passkeys through the Larsal extension.', sw(true, 'Browser')))
    + grp('Browsers', [['safari', 'Safari', true], ['googlechrome', 'Chrome', true], ['firefoxbrowser', 'Firefox', true], ['brave', 'Brave', false], ['vivaldi', 'Vivaldi', false], ['opera', 'Opera', false]].map(([k, l, on]) => row(`<span style="display:inline-flex;gap:10px;align-items:center"><span class="logo">${brandSvg(k)}</span>${l}</span>`, '', sw(on, l))).join(''))
    + grp('When a browser asks', row('Show a notification', '', sw(true, 'Notify')) + row('Ask to unlock a locked vault', '', sw(true, 'Unlock')) + row('Offer only the best matches', '', sw(false, 'Best')) + row('Search every open vault', '', sw(true, 'All vaults')) + row('Never ask before giving access', 'Not recommended: any site that matches gets the entry.', sw(false, 'Never ask')) + row('Allow passkeys on localhost', 'For web developers.', sw(false, 'Localhost')))
    + grp('Advanced', row('Use a custom proxy location', '', sw(false, 'Proxy')) + row('Rewrite the browser setup files at start', '', sw(true, 'Rewrite'))),
  ssh: () => grp('', row('Work with the SSH agent', 'Adds keys from entries to the system agent.', sw(true, 'SSH')))
    + grp('Agent', row('Status', '<span class="mono">/private/tmp/com.apple.launchd.Kp9w/Listeners</span>', `<span class="pill pos">${icf('check-circle')}Connected</span>`) + row('Use a different socket', '', sw(false, 'Socket')) + row('Security key provider', 'For sk-ed25519 keys on a hardware key.', selx('Built-in'))),
  share: () => grp('', row('Import shared groups', 'Reads groups other people share with you through a synced folder.', sw(true, 'Import')) + row('Export shared groups', '', sw(true, 'Export')) + row('Do not show sharing messages', '', sw(false, 'Quiet')))
    + grp('Your identity', row('Alex Morgan', '<span class="mono">SHA256:Qm4…8sT1</span>', '<button class="btn sm">Export certificate…</button>')),
  keys: () => grp('Entries', [['Copy Username', '⌘B'], ['Copy Password', '⌘C'], ['Copy URL', '⇧⌘U'], ['Copy One-Time Code', '⌘T'], ['Type Login', '⇧⌘V'], ['Open URL', '⌘U'], ['Edit Entry', '⌘E'], ['Clone Entry', '⌘D'], ['Delete Entry', '⌘⌫']].map(([t, k]) => row(t, '', kbd(k))).join(''))
    + grp('Larsal', [['Lock Vault', '⌘L'], ['Lock Everything', '⇧⌘L'], ['Password Generator', '⌥⌘G'], ['Reports', '⇧⌘R'], ['Vault Settings', '⇧⌘,'], ['Show Sidebar', '⌃⌘S']].map(([t, k]) => row(t, '', kbd(k))).join('')),
};
function settingsWin(s, items = SETTINGS, pages = SETP, title = '') {
  const p = s.page || items[0][0], it = items.find((x) => x[0] === p);
  return `<div class="set"><aside class="snav"><div class="lights"><i></i><i></i><i></i></div>${title ? `<div style="display:flex;gap:10px;align-items:center;padding:0 8px 14px">${tile('--teal', 'keyhole', 'md')}<span><b style="display:block;font-weight:600">Personal</b><small style="color:var(--muted);font-size:12px">Vault settings</small></span></div>` : `<label class="search">${ic('magnifying-glass')}<input placeholder="Search settings…" aria-label="Search settings"></label>`}
    <ul style="list-style:none;margin:0;padding:0">${items.map(([id, l, c, i]) => `<li><button class="si" data-a="spage" data-v="${id}"${p === id ? ' aria-current="page"' : ''}>${tile(c, i)}<span class="lbl">${l}</span></button></li>`).join('')}</ul></aside>
    <section class="sbody"><div class="shead">${ic('caret-left')}${ic('caret-right')}<b>${it[1]}</b></div><div class="sc">${pages[p](s)}</div></section></div>`;
}
const VSET = [['general', 'General', '--teal', 'keyhole'], ['security', 'Security', '--blue', 'lock-key'], ['bin', 'Recycle Bin', '--gray', 'trash'], ['history', 'History', '--orange', 'clock-counter-clockwise'], ['browser', 'Browser Keys', '--teal', 'globe-simple']];
const VSETP = {
  general: () => `<div class="fgrid" style="margin-bottom:24px">${fieldRow('Name', inp('Personal'))}${fieldRow('Default username', inp('alex.morgan@posteo.de'))}${fieldRow('Description', `<textarea class="ta" style="min-height:72px">Everything that is mine, not work.</textarea>`, '', true)}</div>`
    + grp('Colour and icon', row('Shown in the sidebar and on the lock screen', '', `<div class="swatches">${['--teal', '--blue', '--green', '--orange', '--pink', '--purple', '--slate'].map((c, i) => `<button style="--c:var(${c})" aria-pressed="${i === 0}" aria-label="${c.slice(2)}"></button>`).join('')}</div>`))
    + grp('File', row('Location', '<span class="mono">~/Documents/Passwords/Personal.larsalvault</span>', '<button class="btn sm">Show in Finder</button>') + row('Format', 'Version 4.1 · 84 KB', '')),
  security: () => grp('Credentials', row('Password', 'Changed Mar 3, 2024', '<button class="btn sm">Change…</button>') + row('Key file', 'personal.larsalkey', '<button class="btn sm">Change…</button><button class="btn sm" style="color:var(--negative)">Remove</button>') + row(`<span style="display:inline-flex;gap:8px;align-items:center">${brandSvg('yubico', 16)}Security key</span>`, 'YubiKey 5 NFC · slot 2 · challenge-response', '<button class="btn sm">Change…</button>') + row('Touch ID for this vault', '', sw(true, 'Touch ID')))
    + grp('Encryption', row('Cipher', '', selx('AES-256')) + row('Key derivation', 'Argon2id resists guessing on graphics cards.', selx('Argon2id')) + row('Unlock time on this Mac', 'Higher means slower guessing for an attacker.', `<input class="range" type="range" style="width:160px" value="40"><span class="num" style="width:44px;text-align:right">1.0 s</span>`) + row('Memory', '', stepper(64, 'MiB')) + row('Parallel threads', '', stepper(2)))
    + `<p class="help" style="margin:10px 2px 0">Changes take effect the next time Larsal saves. Older apps may not open a vault that uses ChaCha20 or more than 1 GiB of memory.</p>`,
  bin: () => grp('', row('Use a Recycle Bin', 'Deleted entries wait here until you empty it.', sw(true, 'Bin')) + row('Empty entries older than', '', stepper(90, 'days') + sw(false, 'Auto empty'))),
  history: () => grp('', row('Keep earlier versions of entries', '', sw(true, 'History')) + row('Versions per entry', '', stepper(10)) + row('History size per entry', '', stepper(6, 'MB')) + row('Space used now', '4.8 KB in 18 versions', '<button class="btn sm" style="color:var(--negative)">Delete all history…</button>')),
  browser: () => grp('Connected browsers', row(`<span style="display:inline-flex;gap:10px;align-items:center">${brandSvg('firefoxbrowser', 18)}Firefox on MacBook</span>`, 'Connected Oct 12 · last used today, 09:12', '<button class="btn sm" style="color:var(--negative)">Disconnect</button>') + row(`<span style="display:inline-flex;gap:10px;align-items:center">${brandSvg('safari', 18)}Safari</span>`, 'Connected Sep 3 · last used Oct 20', '<button class="btn sm" style="color:var(--negative)">Disconnect</button>'))
    + grp('Stored permissions', row('Site permissions kept in entries', '4 entries hold allowed or blocked sites', '<button class="btn sm">Remove all…</button>')),
};

// ---------- welcome and new-vault wizard ----------
function welcomeWin() {
  return `<div class="wel"><div class="l"><div class="lights"><i></i><i></i><i></i></div><div style="margin-top:40px">${tile('--teal', 'keyhole', 'xl')}</div><h1>Larsal</h1><p>Your passwords, in a file you own.</p>
    <div class="acts">${[['plus', '--blue', 'New vault', 'An encrypted file for your passwords'], ['folder-open', '--orange', 'Open vault…', 'A vault file on this Mac or a synced folder'], ['download-simple', '--green', 'Import…', 'From CSV or another password manager']].map(([i, c, t, d]) => `<button class="act">${tile(c, i, 'md')}<span><b>${t}</b><small>${d}</small></span></button>`).join('')}</div>
    <div style="margin-top:auto;font-size:12px;color:var(--muted)">Version 1.0 · source available</div></div>
    <section class="r"><h2>Recent vaults</h2>${VAULTS.map((v, i) => `<button class="rec">${tile(v.c, v.icon, 'md')}<span class="who"><b>${v.name}</b><small>${v.path}</small></span><span class="when">${['Today', 'Yesterday', 'Oct 18'][i]}</span></button>`).join('')}
    <div style="margin-top:auto" class="help">Drag a vault file here to open it.</div></section></div>`;
}
function wizard(stepN) {
  const steps = ['Name', 'Encryption', 'Password'];
  const head = `<div class="steps">${steps.map((t, i) => `<div class="${i < stepN ? 'done' : i === stepN ? 'on' : ''}"><i></i><span>${t}</span></div>`).join('')}</div>`;
  const body = [
    `<h2>Name your vault</h2><p>The name shows in the sidebar and on the lock screen.</p><div class="fgrid">${fieldRow('Name', inp('Family'), '', true)}${fieldRow('Description <small>· optional</small>', '<textarea class="ta" style="min-height:80px">Streaming, the router and the kids’ school accounts.</textarea>', '', true)}${fieldRow('Save in', `<div class="inp">${ic('folder-simple')}<span style="flex:1">iCloud Drive › Passwords</span><button class="btn sm">Change…</button></div>`, 'Family.larsalvault. A synced folder keeps it on your other Macs.', true)}</div>`,
    `<h2>Encryption</h2><p>The defaults suit almost everyone. They match what security reviews recommend today.</p>
      <div class="choices"><button class="choice" aria-checked="true">${rb(true)}<span><b>Recommended</b><small>AES-256 with Argon2id. About 1 second to unlock on this Mac, and very slow to guess on other hardware.</small></span></button>
      <button class="choice" aria-checked="false">${rb(false)}<span><b>Custom</b><small>Choose the cipher, memory and unlock time yourself.</small></span></button></div>
      <div class="grp" style="margin-top:20px;opacity:.6"><div class="box">${row('Cipher', '', selx('AES-256'))}${row('Key derivation', '', selx('Argon2id'))}${row('Unlock time', '', '<span class="num">1.0 s</span>')}${row('Memory', '', '<span class="num">64 MiB</span>')}</div></div>`,
    `<h2>Choose a password</h2><p>You need it to open the vault. Larsal cannot recover it.</p><div class="fgrid">
      <div class="span"><label class="lab">Password <small>· Strong, about 78 bits</small></label><div class="inp lg"><span class="pw" style="font-size:15px">${pwHtml('orchid-meteor-pine-quartz-41')}</span>${ibtn('eye-slash', 'Hide')}${ibtn('password', 'Generate')}</div><div class="bar" style="height:3px;margin-top:8px"><i style="width:62%;background:var(--positive)"></i></div></div>
      ${fieldRow('Repeat it', `<div class="inp lg"><span class="pw" style="flex:1;font-size:15px">${dots(28)}</span><i class="ph-fill ph-check-circle" style="color:var(--positive);font-size:18px;margin-right:6px"></i></div>`, '', true)}</div>
      <div class="grp" style="margin-top:20px"><h4>More protection <small style="font-weight:400;color:var(--muted)">· optional</small></h4><div class="box">${row(`<span style="display:inline-flex;gap:8px;align-items:center">${ic('file-lock')}Key file</span>`, 'A second secret kept in a file. Without it the vault does not open.', '<button class="btn sm">Create…</button><button class="btn sm">Choose…</button>')}${row(`<span style="display:inline-flex;gap:8px;align-items:center">${brandSvg('yubico', 16)}Security key</span>`, 'A YubiKey or OnlyKey with challenge-response.', '<button class="btn sm">Add…</button>')}${row(`<span style="display:inline-flex;gap:8px;align-items:center">${ic('fingerprint')}Touch ID</span>`, 'Unlock with your finger after the first time.', sw(true, 'Touch ID'))}</div></div>`,
  ][stepN];
  return `<div class="wiz"><div class="wtop"><div class="lights"><i></i><i></i><i></i></div><b>New vault</b></div><div class="wmain">${head}<div class="wbody">${body}</div>
    <div class="wfoot"><button class="btn lg left">Cancel</button>${stepN ? '<button class="btn lg">Back</button>' : ''}<button class="btn lg primary">${stepN === 2 ? 'Create vault' : 'Continue'}</button></div></div></div>`;
}

// ---------- dialogs ----------
const dlg = (c, icon, title, text, body, foot, cls = '') => `<div class="dlg ${cls}" role="dialog" aria-label="${esc(title.replace(/<[^>]+>/g, ''))}"><div class="dh">${tile(c, icon, 'lg')}<div><h3>${title}</h3>${text ? `<p class="dt">${text}</p>` : ''}</div></div>${body ? `<div class="db">${body}</div>` : ''}<div class="df">${foot}</div></div>`;
const cancel = (l = 'Cancel') => `<button class="btn lg" data-a="dclose">${l}</button>`;
const chk = (on, t, d = '') => `<button class="chkrow" data-a="cbx">${cb(on)}<span>${t}${d ? `<small>${d}</small>` : ''}</span></button>`;
const DIALOGS = {
  delete: () => dlg('--red', 'trash', 'Move “Amazon” to the Recycle Bin?', 'You can restore it until you empty the Recycle Bin.', chk(false, 'Do not ask again'), cancel() + '<button class="btn lg danger" data-a="dclose">Move to Recycle Bin</button>'),
  deleteForever: () => dlg('--red', 'trash', 'Delete “MySpace” forever?', 'The entry and its history leave the vault. You cannot undo this.', '', cancel() + '<button class="btn lg danger" data-a="dclose">Delete Forever</button>'),
  emptyBin: () => dlg('--red', 'trash', 'Empty the Recycle Bin?', `${plural(bin.length, 'entry is', 'entries are')} deleted for good: Twitter (old account) and MySpace.`, '', cancel() + '<button class="btn lg danger" data-a="dclose">Empty Recycle Bin</button>'),
  discard: () => dlg('--orange', 'pencil-simple', 'Discard your changes to “GitHub”?', 'You changed the password and added one tag.', '', '<button class="btn lg" data-a="dclose">Keep Editing</button><button class="btn lg danger" data-a="dclose">Discard Changes</button>'),
  clone: () => dlg('--blue', 'copy-simple', 'Clone “GitHub”', 'Makes a copy in the same group.', chk(true, 'Add “ - Clone” to the title') + chk(false, 'Link username and password to the original', 'The copy changes when the original changes.') + chk(false, 'Copy the history'), cancel() + '<button class="btn lg primary" data-a="dclose">Clone</button>'),
  totpSetup: () => dlg('--teal', 'clock-countdown', 'Add a one-time code', 'Paste the secret key or the otpauth:// link the website shows when you turn on two-step sign-in.', `${inp('JBSW Y3DP EHPK 3PXP', { mono: true, lead: 'key' })}<div class="help">Spaces do not matter. Only letters A–Z and digits 2–7.</div>
      <div class="grp" style="margin-top:16px"><div class="box">${row('Digits', '', `<span class="segc"><button aria-pressed="true">6</button><button>7</button><button>8</button></span>`)}${row('New code every', '', stepper(30, 's'))}${row('Algorithm', '', selx('SHA-1'))}</div></div>`, cancel() + '<button class="btn lg primary" data-a="dclose">Add Code</button>'),
  totpQr: () => dlg('--teal', 'qr-code', 'One-time code for “GitHub”', 'Scan it with another authenticator app. Anyone who sees it can make sign-in codes, so close it when you are done.', `<div style="display:grid;place-items:center;padding:12px;border-radius:10px;background:var(--surface);border:1px solid var(--border)">${qr('github')}</div>`, '<button class="btn lg primary" data-a="dclose">Done</button>'),
  wifiQr: () => dlg('--cyan', 'wifi-high', 'Join “Morgan-Home 5G”', 'Point a phone camera at the code to join the network.', `<div style="display:grid;place-items:center;padding:12px;border-radius:10px;border:1px solid var(--border)">${qr('wifi')}</div>`, '<button class="btn lg primary" data-a="dclose">Done</button>'),
  newGroup: () => dlg('--brown', 'folder-simple', 'New group', 'Groups sort entries, like folders.', `<div class="fgrid">${fieldRow('Name', inp('Travel'), '', true)}${fieldRow('Inside', `<div class="inp"><span style="flex:1">Top level</span>${ic('caret-up-down')}</div>`)}<div><label class="lab">Colour</label><div class="swatches" style="height:36px;align-items:center">${['--blue', '--green', '--orange', '--pink', '--purple', '--cyan'].map((c, i) => `<button style="--c:var(${c})" aria-pressed="${i === 5}" aria-label="${c.slice(2)}"></button>`).join('')}</div></div></div>
      <label class="lab" style="margin-top:16px">Icon</label><div class="icongrid" style="grid-template-columns:repeat(8,1fr)">${['airplane', 'suitcase', 'map-pin', 'globe-simple', 'house-line', 'car', 'train', 'boat'].map((n, i) => `<button aria-pressed="${i === 0}" aria-label="${n}">${ic(n)}</button>`).join('')}</div>`, cancel() + '<button class="btn lg primary" data-a="dclose">Create Group</button>'),
  passkeyRemove: () => dlg('--purple', 'fingerprint', 'Remove the passkey for github.com?', 'You can no longer sign in to github.com with it. The password and the one-time code stay.', '', cancel() + '<button class="btn lg danger" data-a="dclose">Remove Passkey</button>'),
  histShow: () => dlg('--orange', 'clock-counter-clockwise', 'GitHub, Jun 3, 2026 at 11:20', 'How the entry looked before the passkey was added.', `<div class="panel">${fld('Username', 'alex-dev')}${fld('Password', `<span class="pw">${pwHtml('m8@Ty3!Kq6#Pv1$Zr4&')}</span>`)}${fld('Website', 'github.com/login')}</div>`, cancel('Close') + '<button class="btn lg primary" data-a="dclose">Restore This Version</button>'),
  disk: () => dlg('--blue', 'arrows-clockwise', 'Personal.larsalvault changed on disk', 'Another app saved it at 10:24, after you opened it. You have 2 changes that are not saved yet.', `<div class="choices"><button class="choice" aria-checked="true">${rb(true)}<span><b>Merge</b><small>Keep both. For an entry changed in both places, the newer version wins and the other goes to its history.</small></span></button><button class="choice" aria-checked="false">${rb(false)}<span><b>Reload</b><small>Open the version on disk. Your 2 changes are lost.</small></span></button><button class="choice" aria-checked="false">${rb(false)}<span><b>Keep mine</b><small>Save over the file on disk.</small></span></button></div>`, cancel('Decide Later') + '<button class="btn lg primary" data-a="dclose">Merge</button>', 'wide'),
  closeUnsaved: () => dlg('--teal', 'floppy-disk', 'Save changes to “Personal” before closing?', 'You have 2 changes that are not saved yet.', '', '<button class="btn lg left" data-a="dclose">Don’t Save</button>' + cancel() + '<button class="btn lg primary" data-a="dclose">Save</button>'),
  saveFailed: () => dlg('--red', 'warning-circle', 'Larsal could not save “Personal”', 'The disk “Backup SSD” is not connected. Your changes are safe in memory until you quit.', '', '<button class="btn lg left">Save As…</button>' + cancel('Close') + '<button class="btn lg primary" data-a="dclose">Try Again</button>'),
  exportCsv: () => dlg('--orange', 'warning', 'Export without encryption?', 'The CSV file holds every password in plain text. Anyone who opens the file can read them, and sync services may keep copies.', chk(true, 'I understand. Export the 23 entries of “Personal”'), cancel() + '<button class="btn lg danger" data-a="dclose">Export CSV…</button>'),
  importDlg: () => dlg('--green', 'download-simple', 'Import into “Personal”', 'Larsal reads the file on this Mac. Nothing is uploaded.', `<div class="panel" style="padding:4px 16px">${row('From', '', selx('Bitwarden (JSON)'))}${row('File', '<span class="mono">bitwarden_export_20261027.json</span>', '<button class="btn sm">Choose…</button>')}</div>
      <div class="notice neu" style="margin-top:12px">${ic('check-circle')}<div><b>Ready to import 61 items:</b> 48 logins, 3 cards, 6 notes and 4 folders. They go into a new group “Imported Oct 27”. 2 have no password and come in as notes.</div></div>`, cancel() + '<button class="btn lg primary" data-a="dclose">Import 61 Items</button>', 'wide'),
  browserAccess: () => dlg('--teal', 'globe-simple', 'Firefox asks for a sign-in on github.com', 'Choose the entries Firefox may use on this site.', `<div class="panel" style="padding:4px 12px">${[byId('github'), E({ title: 'GitHub (work bot)', username: 'morgan-labs-ci', brand: 'github' })].map((e, i) => `<button class="chkrow" style="padding:10px 0;align-items:center${i ? ';border-top:1px solid var(--rule)' : ''}">${cb(i === 0)}${logo(e, 'xs')}<span><b style="font-weight:500">${esc(e.title)}</b><small>${esc(e.username)}</small></span></button>`).join('')}</div>${chk(true, 'Remember for github.com')}`, '<button class="btn lg" data-a="dclose">Deny</button><button class="btn lg primary" data-a="dclose">Allow Selected</button>'),
  browserConnect: () => dlg('--teal', 'plugs-connected', 'Connect a new browser?', 'A Larsal extension asks to connect to “Personal”. Name it so you know it later. Only allow it if you just installed the extension.', fieldRow('Name', inp('Firefox on MacBook')), '<button class="btn lg" data-a="dclose">Deny</button><button class="btn lg primary" data-a="dclose">Connect</button>'),
  sshConfirm: () => dlg('--graphite', 'terminal-window', 'Allow ssh to use “Server root · web-01”?', 'ssh wants to sign in to 203.0.113.10 with this key.', '', '<button class="btn lg" data-a="dclose">Deny</button><button class="btn lg primary" data-a="dclose">Allow Once</button>'),
  weakMaster: () => dlg('--orange', 'warning', 'This password is easy to guess', '“family2026” could be guessed in about 2 hours on a graphics card. Anyone with a copy of the vault file could open it.', '', '<button class="btn lg left" data-a="dclose">Use It Anyway</button><button class="btn lg primary" data-a="dclose">Choose Another</button>'),
  keyFile: () => dlg('--blue', 'file-lock', 'Create a key file', 'A key file is a second secret. Keep a copy somewhere safe: without it the vault does not open.', `${fieldRow('Save as', `<div class="inp">${ic('file-lock')}<span style="flex:1" class="mono">family.larsalkey</span><button class="btn sm">Change…</button></div>`)}<div class="help">Do not keep it next to the vault in the same synced folder.</div>`, cancel() + '<button class="btn lg primary" data-a="dclose">Create Key File</button>'),
};

const DNAMES = { delete: 'Move to Recycle Bin', deleteForever: 'Delete forever', emptyBin: 'Empty Recycle Bin', discard: 'Discard changes', clone: 'Clone entry', totpSetup: 'Add one-time code', totpQr: 'One-time code as QR', wifiQr: 'Wi-Fi as QR', newGroup: 'New group', passkeyRemove: 'Remove passkey', histShow: 'Earlier version', disk: 'Changed on disk', closeUnsaved: 'Close with unsaved changes', saveFailed: 'Save failed', exportCsv: 'Export warning', importDlg: 'Import', browserAccess: 'Browser asks for an entry', browserConnect: 'Connect a browser', sshConfirm: 'SSH key use', weakMaster: 'Weak vault password', keyFile: 'Create key file' };

// ---------- menu bar and floating panels ----------
function menuBarWin() {
  return `<div class="mbar"><b></b><b>Larsal</b><span>File</span><span>Edit</span><span>Vault</span><span>Entry</span><span>View</span><span class="sp"></span><span class="on">${icf('keyhole')}</span><span>${ic('wifi-high')}</span><span class="num">Tue 27 Oct 10:30</span></div><div class="desk"></div>
    <div class="menu" style="top:32px;right:118px;width:290px"><div class="mh">Vaults</div>${VAULTS.map((v) => `<button class="mi">${tile(v.c, v.icon)}${v.name}<span class="k">${v.locked ? ic('lock-simple') : 'Unlocked'}</span></button>`).join('')}<div class="msep"></div>
      <button class="mi">${ic('magnifying-glass')}Search Entries…<span class="k">⌥⌘Space</span></button><button class="mi">${ic('password')}Password Generator<span class="k">⌥⌘G</span></button><button class="mi">${ic('lock-key')}Lock Everything<span class="k">⇧⌘L</span></button><div class="msep"></div>
      <button class="mi">${ic('app-window')}Show Larsal</button><button class="mi">${ic('gear-six')}Settings…<span class="k">⌘,</span></button><button class="mi">${ic('power')}Quit Larsal<span class="k">⌘Q</span></button></div>`;
}
function autotypePicker() {
  const opts = [byId('github'), E({ title: 'GitHub (work bot)', username: 'morgan-labs-ci', brand: 'github' })];
  return `<div class="desk" style="inset:0"></div><div class="dlg" style="position:absolute;top:40px;left:50%;transform:translateX(-50%);width:480px;padding:16px">
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:12px">${ic('keyboard')}<b style="font-weight:600">Type into “Sign in to GitHub · GitHub — Safari”</b></div>
    <label class="search" style="width:100%">${ic('magnifying-glass')}<input placeholder="Search all entries…"></label>
    <div style="margin-top:8px">${opts.map((e, i) => `<button class="rec" style="${i === 0 ? 'background:var(--active)' : ''}">${logo(e)}<span class="who"><b>${esc(e.title)}</b><small>${esc(e.username)}</small></span><span class="when">${i === 0 ? 'Type login ⏎' : ''}</span></button>`).join('')}</div>
    <div class="help" style="margin-top:8px">↑↓ to choose · ⏎ types username, password and code · ⇧⏎ types the password only</div></div>`;
}

// ---------- browser extension (E7-S7, INT-01 to INT-04) ----------
const BOT = E({ id: 'ghbot', title: 'GitHub (work bot)', username: 'morgan-labs-ci', brand: 'github', password: 'Qz8!vK3@rN6#tW1$', modified: '2026-09-02T10:00' });
function browser({ url, tab, brand, page, over = '', badge = '', xon = false }) {
  return `<div class="bw"><div class="btabs"><div class="lights"><i></i><i></i><i></i></div><div class="btab">${brand ? brandSvg(brand, 14) : ic('globe-simple')}<span>${esc(tab)}</span>${ic('x')}</div></div>
    <div class="btool">${ic('arrow-left')}${ic('arrow-right')}${ic('arrow-clockwise')}<div class="omni">${ic('lock-simple')}<span><b>${esc(url.split('/')[0])}</b>${esc(url.slice(url.indexOf('/')))}</span></div>
      <span class="xbtn${xon ? ' on' : ''}" title="Larsal">${tile('--teal', 'keyhole')}${badge ? `<span class="cnt num">${badge}</span>` : ''}</span><span class="xbtn">${ic('puzzle-piece')}</span><span class="xbtn">${ic('user-circle')}</span></div>
    <div class="bpage${page.app ? ' app' : ''}">${page.html}${over}</div></div>`;
}
const larsalMark = () => tile('--teal', 'keyhole');
function site({ brand, title, fields, button, note = '' }) {
  return { html: `<div class="site"><div class="slogo">${brandSvg(brand, 44)}</div><h1>${title}</h1><div class="sitecard">${fields.map((f) => `<div class="sitef"><label>${f.label}</label><div class="in${f.focus ? ' focus' : ''}"><span${f.mono ? ' class="mono"' : ''}>${f.value || ''}</span>${f.mark ? larsalMark() : ''}</div>${f.menu || ''}</div>`).join('')}<div class="sitebtn">${button}</div></div>${note ? `<div class="sitenote">${note}</div>` : ''}</div>` };
}
const ghLogin = (opts = {}) => site({ brand: 'github', title: 'Sign in to GitHub', fields: [{ label: 'Username or email address', value: opts.user || '', focus: opts.focusUser, mark: true, menu: opts.menu }, { label: 'Password', value: opts.pw ? dots(20) : '', mark: true }], button: 'Sign in', note: 'New to GitHub? Create an account' });
const xHead = (sub) => `<div class="xh">${tile('--teal', 'keyhole', 'md')}<span class="who"><b>Personal</b><small>${sub}</small></span>${ibtn('arrow-square-out', 'Open Larsal')}${ibtn('lock-simple', 'Lock Personal')}</div>`;
const xSearch = (q = '') => `<label class="search">${ic('magnifying-glass')}<input value="${esc(q)}" placeholder="Search Personal…" aria-label="Search entries">${q ? ibtn('x-circle', 'Clear search', '', '', 'sm') : ''}</label>`;
const xNav = (on) => `<nav class="xn">${[['entries', 'key', 'Entries'], ['codes', 'clock-countdown', 'Codes'], ['gen', 'password', 'Generator'], ['settings', 'gear-six', 'Settings']].map(([k, i, l]) => `<button${on === k ? ' aria-current="page"' : ''}>${ic(i)}${l}</button>`).join('')}</nav>`;
const xRow = (e, act, cls = '') => `<div class="xr ${cls}">${logo(e)}<span class="who"><b>${esc(e.title)}</b><small>${esc(e.username)}</small></span>${act}</div>`;
const fillBtns = (primary) => `<button class="btn sm${primary ? ' primary' : ''}">Fill</button>${ibtn('copy', 'Copy password', '', '', 'sm')}`;
const popup = (inner) => `<div class="xp" role="dialog" aria-label="Larsal">${inner}</div>`;
const EXT = {
  matches: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), badge: '2', xon: true, over: popup(`${xHead('github.com · 2 matches')}${xSearch()}<div class="xsec">For github.com</div>${xRow(byId('github'), fillBtns(true), 'on')}${xRow(BOT, fillBtns())}
      <div class="xsec">One-time code · GitHub</div><div class="xr"><span class="who"><span class="code num" data-totp="github">${fmtCode(code('github', step()))}</span><div class="bar" style="margin-top:6px"><i data-tick></i></div></span><button class="btn sm">Fill code</button>${ibtn('copy', 'Copy code', '', '', 'sm')}</div>
      <div class="xsec">Recently used</div>${xRow(byId('google'), ibtn('copy', 'Copy password', '', '', 'sm'))}${xNav('entries')}`) }),
  detail: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), badge: '2', xon: true, over: popup(`<div class="xh">${ibtn('arrow-left', 'Back')}${logo(byId('github'))}<span class="who"><b>GitHub</b><small>github.com</small></span>${ibtn('arrow-square-out', 'Open in Larsal')}</div>
      <div style="padding:0 12px"><div class="panel">${fld('Username', 'alex-dev', ibtn('copy', 'Copy username', '', '', 'sm'))}${fld('Password', `<span class="pw">${dots(20)}</span>`, ibtn('eye', 'Show password', '', '', 'sm') + ibtn('copy', 'Copy password', '', '', 'sm'))}<div class="fld otp"><div><span class="lb">One-time code</span><span class="big num" data-totp="github" style="font-size:22px;line-height:28px">${fmtCode(code('github', step()))}</span><div class="secs num" data-secs></div></div>${ibtn('copy', 'Copy code', '', '', 'sm')}</div>${fld('Passkey', 'github.com · alex-dev', `<span class="ibtn sm" style="cursor:default">${ic('fingerprint')}</span>`)}</div>
      <div style="display:flex;gap:8px;margin:12px 0 4px"><button class="btn lg primary" style="flex:1">${ic('key-return')}Fill sign-in</button><button class="btn lg">Fill code</button></div><p class="help" style="margin:0 0 12px">Fills the username and password, then waits for you to press Sign in.</p></div>${xNav('entries')}`) }),
  search: () => { const res = visible({ view: 'all', q: 'ne' }); return browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), badge: '2', xon: true, over: popup(`${xHead(`${res.length} results in Personal`)}${xSearch('ne')}<div class="xsec">All entries</div>${res.slice(0, 5).map((e, i) => xRow(e, `${ibtn('user', 'Copy username', '', '', 'sm')}${ibtn('copy', 'Copy password', '', '', 'sm')}`, i === 0 ? 'on' : '')).join('')}<p class="help" style="margin:6px 14px 4px">These do not match github.com, so Larsal asks before filling them here.</p>${xNav('entries')}`) }); },
  gen: () => browser({ url: 'linear.app/signup', tab: 'Create your account · Linear', brand: 'linear', page: site({ brand: 'linear', title: 'Create your Linear account', fields: [{ label: 'Work email', value: 'alex@morgan-labs.dev' }, { label: 'Password', value: '', focus: true, mark: true }], button: 'Continue' }), xon: true, over: popup(`${xHead('Generator')}${generator({ glen: 20, ext: true, seed: 3 })}${xNav('gen')}`) }),
  locked: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), xon: true, over: popup(`<div class="xcenter">${tile('--teal', 'keyhole', 'xl')}<h3>Personal is locked</h3><p>Unlock it in Larsal. You confirm with Touch ID in Larsal, so your vault password never goes through the browser.</p><button class="btn xl primary wide">${ic('fingerprint')}Unlock in Larsal</button><button class="btn ghost" style="margin-top:8px">Other vaults: Work, Family ${ic('caret-down')}</button></div>`) }),
  offline: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), xon: true, over: popup(`<div class="xcenter">${tile('--gray', 'plugs-connected', 'lg')}<h3>Larsal is not reachable</h3><p>The extension talks only to the Larsal on this Mac. Check these, then try again.</p>
      <div class="xchecks"><div>${icf('check-circle', '')}<span style="flex:1">Larsal is installed<br><small style="color:var(--muted)">Version 1.0 in Applications</small></span></div><div><i class="ph-fill ph-x-circle" style="color:var(--negative)"></i><span style="flex:1">Larsal is running<br><small style="color:var(--muted)">Open Larsal, then click Try Again</small></span></div><div><i class="ph-fill ph-circle-dashed" style="color:var(--muted)"></i><span style="flex:1">Browser Integration is on for Chrome<br><small style="color:var(--muted)">Settings › Browser Integration</small></span></div></div>
      <div style="display:flex;gap:8px;width:100%"><button class="btn lg" style="flex:1">Try Again</button><button class="btn lg primary" style="flex:1">Open Larsal</button></div></div>`) }).replace('class="ph-fill ph-check-circle "', 'class="ph-fill ph-check-circle" style="color:var(--positive)"'),
  pairing: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), xon: true, over: popup(`<div class="xcenter">${tile('--teal', 'plugs-connected', 'lg')}<h3>Connect Chrome to Larsal</h3><p>Switch to Larsal and allow the connection. Check that Larsal shows the same four words.</p><div class="words">${['harbor', 'quill', 'ember', 'forty-two'].map((w) => `<span>${w}</span>`).join('')}</div><div class="help" style="margin:0 0 16px">${ic('hourglass')} Waiting for Larsal…</div><button class="btn lg wide">Cancel</button></div>`) }),
  inline: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin({ focusUser: true, menu: `<div class="xi" role="listbox" aria-label="Fill from Larsal"><div class="xih">${larsalMark()}Larsal · Personal · 2 matches</div>${xRow(byId('github'), '<span class="k">⏎</span>', 'on')}${xRow(BOT, '')}<div class="msep"></div><button class="mi">${ic('clock-countdown')}Fill one-time code next<span class="k">GitHub</span></button><button class="mi">${ic('magnifying-glass')}Search Personal…</button></div>` }), badge: '2' }),
  otp: () => browser({ url: 'github.com/sessions/two-factor', tab: 'Two-factor authentication', brand: 'github', page: site({ brand: 'github', title: 'Two-factor authentication', fields: [{ label: 'Authentication code', value: '', focus: true, mark: true, menu: `<div class="xi" style="top:62px"><div class="xih">${larsalMark()}Larsal · one-time code</div><div class="xr on">${logo(byId('github'))}<span class="who"><b class="code num" data-totp="github">${fmtCode(code('github', step()))}</b><small>GitHub · alex-dev</small></span><span class="k num" data-secs-short></span></div></div>` }], button: 'Verify', note: 'Open your authenticator app or Larsal to view your code.' }), badge: '1' }),
  signup: () => browser({ url: 'linear.app/signup', tab: 'Create your account · Linear', brand: 'linear', page: site({ brand: 'linear', title: 'Create your Linear account', fields: [{ label: 'Work email', value: 'alex@morgan-labs.dev' }, { label: 'Password', value: '', focus: true, mark: true, menu: `<div class="xi"><div class="xih">${larsalMark()}Larsal · new password</div><div class="xr on" style="min-height:58px">${ic('password')}<span class="who"><b>Use a strong password</b><small class="mono">${esc(generate({ glen: 20, seed: 3 }))}</small></span><span class="k">⏎</span></div><button class="mi">${ic('sliders-horizontal')}Open the generator…</button><p class="help" style="margin:4px 8px 6px">Larsal saves it as a new entry for linear.app once you continue.</p></div>` }], button: 'Continue' }), badge: '' }),
  save: () => browser({ url: 'www.reddit.com/register', tab: 'Reddit · Sign up', brand: 'reddit', page: site({ brand: 'reddit', title: 'Welcome to Reddit', fields: [{ label: 'Username', value: 'alex_morgan_dev' }, { label: 'Password', value: dots(16) }], button: 'Continue' }), xon: true, over: `<div class="xprompt" role="dialog" aria-label="Save this sign-in"><div class="ph-head">${larsalMark()}<b>Save this sign-in?</b>${ibtn('x', 'Close', '', '', 'sm')}</div>
      <div class="panel">${fld('Title', `<span style="display:inline-flex;gap:8px;align-items:center">${logo(byId('reddit'), 'xs')}Reddit (alex_morgan_dev)</span>`)}${fld('Username', 'alex_morgan_dev')}${fld('Password', `<span class="pw">${dots(16)}</span> <span class="pill pos" style="margin-left:6px">Strong</span>`, ibtn('eye', 'Show password', '', '', 'sm'))}${fld('Group', `<span style="display:inline-flex;gap:8px;align-items:center">${tile('--pink', 'users-three')}Social</span>`, ic('caret-up-down'))}</div>
      <p class="help">Reddit already has an entry for alex_m. This adds a second one.</p><div class="df"><button class="btn left ghost">Never for this site</button><button class="btn">Not Now</button><button class="btn primary">Save</button></div></div>` }),
  update: () => browser({ url: 'www.amazon.de/ap/cnep', tab: 'Amazon · Change password', page: { html: `<div class="site"><div class="slogo"><span class="logo lg letter" style="--h:${hue('Amazon')}">A</span></div><h1>Your password was changed</h1><div class="sitecard"><div class="sitef"><label>New password</label><div class="in"><span>${dots(22)}</span>${larsalMark()}</div></div><div class="sitebtn">Continue shopping</div></div></div>` }, xon: true, over: `<div class="xprompt" role="dialog" aria-label="Update password"><div class="ph-head">${larsalMark()}<b>Update the password for Amazon?</b>${ibtn('x', 'Close', '', '', 'sm')}</div>
      <div class="panel">${fld('Entry', `<span style="display:inline-flex;gap:8px;align-items:center">${logo(byId('amazon'), 'xs')}Amazon · alex.morgan@posteo.de</span>`)}<div class="fld"><div><span class="lb">Password</span><span class="v" style="display:flex;gap:8px;align-items:center"><span class="pill neg">Reused</span>${ic('arrow-right')}<span class="pill pos">Strong · 22 characters</span></span></div></div></div>
      <p class="help">The old password goes to the entry's history. eBay still uses it: change that one next.</p><div class="df"><button class="btn">Not Now</button><button class="btn primary">Update</button></div></div>` }),
  passkeySave: () => browser({ url: 'www.paypal.com/myaccount/security', tab: 'PayPal · Security', brand: 'paypal', page: site({ brand: 'paypal', title: 'Create a passkey', fields: [{ label: 'Account', value: 'alex.morgan@posteo.de' }], button: 'Create passkey' }), xon: true, over: `<div class="xprompt" role="dialog" aria-label="Save passkey"><div class="ph-head">${tile('--purple', 'fingerprint')}<b>Save a passkey for paypal.com?</b>${ibtn('x', 'Close', '', '', 'sm')}</div>
      <div class="choices"><button class="choice" aria-checked="true">${rb(true)}<span style="flex:1"><b>Add to PayPal</b><small>alex.morgan@posteo.de · the entry keeps its password</small></span>${logo(byId('paypal'), 'xs')}</button><button class="choice" aria-checked="false">${rb(false)}<span><b>New entry</b><small>In Banking</small></span></button></div>
      <div class="df"><button class="btn left ghost">Use another device</button><button class="btn">Cancel</button><button class="btn primary">Save Passkey</button></div></div>` }),
  passkeyUse: () => browser({ url: 'github.com/login', tab: 'Sign in to GitHub', brand: 'github', page: ghLogin(), xon: true, over: `<div class="xprompt" role="dialog" aria-label="Sign in with a passkey"><div class="ph-head">${tile('--purple', 'fingerprint')}<b>Sign in to github.com with a passkey</b>${ibtn('x', 'Close', '', '', 'sm')}</div>
      <div class="panel" style="padding:4px 0">${xRow(byId('github'), `<span class="pill neu">${ic('fingerprint')}passkey</span>`, 'on')}</div><p class="help">Larsal confirms with Touch ID before it signs in.</p>
      <div class="df"><button class="btn left ghost">Use another device</button><button class="btn">Cancel</button><button class="btn primary">${ic('fingerprint')}Continue</button></div></div>` }),
  options: () => browser({ url: 'chrome-extension://app/options.html', tab: 'Larsal · Options', page: { app: true, html: `<div class="xopts"><div style="display:flex;gap:14px;align-items:center;margin-bottom:24px">${tile('--teal', 'keyhole', 'lg')}<div><h2 style="margin:0;font-size:20px;font-weight:600">Larsal for Chrome</h2><p style="margin:2px 0 0;color:var(--muted)">Version 1.0 · works with Larsal on this Mac</p></div></div>`
      + grp('Connection', row('Status', 'Connected to Larsal 1.0 as “Chrome on MacBook”', `<span class="pill pos">${icf('check-circle')}Connected</span>`) + row('Vaults', 'Personal unlocked · Work and Family locked', '<button class="btn sm">Open Larsal</button>') + row('Disconnect this browser', 'Larsal forgets this browser. You can connect again later.', '<button class="btn sm" style="color:var(--negative)">Disconnect</button>'))
      + grp('Filling', row('Show the Larsal menu in sign-in fields', '', sw(true, 'Inline menu')) + row('Fill when a page loads', 'Off is safer: a page could hide fields to catch a fill.', sw(false, 'Autofill on load')) + row('Offer to save new sign-ins', '', sw(true, 'Save prompt')) + row('Offer to update changed passwords', '', sw(true, 'Update prompt')) + row('Use Larsal for passkeys', 'Chrome asks Larsal first when a site wants a passkey.', sw(true, 'Passkeys')))
      + grp('Shortcuts', row('Open the Larsal popup', '', kbd('⌥⇧A')) + row('Fill the best match', '', kbd('⌥⇧F')) + row('Generate a password', '', kbd('⌥⇧G')) + row('Change them in chrome://extensions/shortcuts', '', '<button class="btn sm">Open</button>'))
      + grp('Privacy', row('The extension stores no passwords', 'It asks Larsal for each fill over an encrypted channel and keeps nothing after the tab closes.', icf('shield-check'))) + '</div>' } }),
};
const EXT_FRAMES = [
  ['matches', 'Popup · matches for this site', 'Opens from the toolbar icon; the badge counts matches'], ['detail', 'Popup · entry', 'Copy, show, fill'], ['search', 'Popup · search everything', 'Entries that do not match the site'],
  ['gen', 'Popup · generator', 'On a sign-up page'], ['locked', 'Popup · vault locked', 'Unlock happens in Larsal with Touch ID'], ['offline', 'Popup · Larsal not reachable', 'Checks with the fix for each'],
  ['pairing', 'Popup · first connection', 'Pairs with the Connect a browser dialog in Larsal'], ['inline', 'In page · fill menu', 'Under the focused sign-in field'], ['otp', 'In page · one-time code', 'Code field on the second sign-in step'],
  ['signup', 'In page · new password', 'Strong password offered in the field'], ['save', 'In page · save sign-in', 'After a sign-up form is sent'], ['update', 'In page · update password', 'After a password change'],
  ['passkeySave', 'In page · save passkey', 'Site asks to create a passkey'], ['passkeyUse', 'In page · sign in with passkey', 'Touch ID in Larsal confirms'], ['options', 'Extension options', 'chrome-extension:// options page'],
].map(([k, t, n]) => ({ t, n, w: 1100, h: 720, render: () => EXT[k]() }));

// ---------- frames ----------
const base = { view: 'all', tab: 'all', sel: 'github', mode: 'list', sort: 'modified' };
const M = (o) => ({ ...base, ...o });
const SECTIONS = [
  ['main', 'Main window', 'Light and dark side by side. Click rows, tabs, the sidebar, the eye and the copy buttons; ↑ ↓ move through the list. Sidebar tiles use the macOS system colours, like System Settings.', [
    { t: 'Main window · light', n: 'E5-S4 · All entries', s: M({}), theme: 'light' },
    { t: 'Main window · dark', n: 'E5-S4 · near-black, elevation by lightness', s: M({}), theme: 'dark' },
  ]],
  ['states', 'Main window states', 'Every kind of entry and every list state. The theme switch at the top changes all frames below.', [
    { t: 'Needs attention', n: 'Reused password with the fix one click away', s: M({ tab: 'attention', sel: 'amazon' }) },
    { t: 'Card', n: 'Banking group · Visa Debit', s: M({ view: 'banking', sel: 'visa' }) },
    { t: 'Server with SSH key', n: 'Servers group · password shown', s: M({ view: 'servers', sel: 'web01', reveal: true }) },
    { t: 'Wi-Fi', n: 'Devices group', s: M({ view: 'devices', sel: 'wifi' }) },
    { t: 'Favorites, tags open', n: 'Sidebar library and tags', s: M({ view: 'fav', sel: 'proton', tagsOpen: true }) },
    { t: 'Search tips', n: 'Search focused, nothing typed', s: M({ overlay: 'tips' }) },
    { t: 'Search with no result', n: 'Empty result keeps its frame', s: M({ q: 'dropbox' }) },
    { t: 'More menu', n: 'Entry menu with shortcuts (APP-08)', s: M({ overlay: 'more' }) },
    { t: 'Vault switcher', n: 'Open, lock, create, import', s: M({ overlay: 'vault' }) },
    { t: 'Sort menu', n: 'Sorted by title: month headers go away', s: M({ overlay: 'sort', sort: 'title' }) },
    { t: 'Recycle Bin', n: 'Deleted entry with Restore', s: M({ view: 'bin', sel: 'twitter' }) },
    { t: 'Copied', n: 'Clipboard clears itself', s: M({ toast: `${ic('check')}Password copied <small>· clipboard clears in 30 s</small>` }) },
    { t: 'Unsaved changes', n: 'Footer shows the save state', s: M({ dirty: true, sel: 'google' }) },
    { t: 'Delete, as a sheet', n: 'Dialogs drop from the window top', s: M({ tab: 'attention', sel: 'amazon', dialog: 'delete' }) },
    { t: 'New, empty vault', n: 'First run after the wizard', s: M({ mode: 'empty', vault: 'family' }) },
  ]],
  ['lock', 'Lock and welcome', 'When a vault is locked, Larsal shows nothing from inside it: no titles, no groups, only the file name.', [
    { t: 'Locked · Touch ID', n: 'E5-S3 · APP-04 quick unlock', s: M({ mode: 'locked' }) },
    { t: 'Locked · password, key file, security key', n: 'APP-06 message M06-06 shown', s: M({ mode: 'locked', unlock: 'password', err: true }) },
    { t: 'Locked · vault switcher', n: 'Other vaults stay reachable', s: M({ mode: 'locked', unlock: 'password', overlay: 'vault' }) },
    { t: 'Welcome', n: 'No vault open', w: 860, h: 540, render: welcomeWin },
  ]],
  ['editor', 'Entry editor', 'All 8 pages (E5-S5). The editor takes the sheet; the sidebar stays.', ED_PAGES.map(([id, , l]) => ({ t: 'Editor · ' + l, n: id === 'ssh' ? 'Server root · web-01' : 'GitHub', s: M({ mode: 'editor', page: id, edit: id === 'ssh' ? 'web01' : 'github' }) })).concat([{ t: 'New entry', n: 'Password made for you (S-ENTRY-03)', s: M({ mode: 'editor', page: 'entry', isNew: true }) }])],
  ['generator', 'Password generator', 'Opens from the toolbar (⌥⌘G) and from the password field (E5-S6). Drag the slider, switch modes.', [
    { t: 'Generator in the window', n: 'Popover under the toolbar button', s: M({ overlay: 'gen' }) },
    { t: 'Password', n: 'Popover alone', w: 436, h: 420, card: true, s: { glen: 20 }, render: (s) => generator(s) },
    { t: 'Passphrase', n: 'Popover alone', w: 436, h: 420, card: true, s: { gmode: 'phrase', gwords: 5 }, render: (s) => generator(s) },
  ]],
  ['reports', 'Reports', 'Opened from Password health in the sidebar or ⇧⌘R (E5-S7). Every number is computed from the demo vault.', REP.map(([id, l]) => ({ t: 'Reports · ' + l, n: '', s: M({ mode: 'reports', view: 'health', rep: id }) }))],
  ['settings', 'Settings', 'A separate window (⌘,) laid out like macOS System Settings (E5-S9, card APP-01).', SETTINGS.map(([id, l]) => ({ t: 'Settings · ' + l, n: '', w: 900, h: 680, s: { page: id }, render: (s) => settingsWin(s) }))],
  ['vault', 'New vault and vault settings', 'E5-S8, card APP-07: three steps, then the vault opens.', [0, 1, 2].map((i) => ({ t: 'New vault · step ' + (i + 1), n: ['Name', 'Encryption', 'Password'][i], w: 720, h: 720, render: () => wizard(i) }))
    .concat(VSET.map(([id, l]) => ({ t: 'Vault settings · ' + l, n: '⇧⌘,', w: 900, h: 640, s: { page: id }, render: (s) => settingsWin(s, VSET, VSETP, 'vault') })))],
  ['dialogs', 'Dialogs', 'Sheets and alerts. Each one names the object and the consequence; the destructive button is red and never the default.', Object.keys(DIALOGS).map((k) => ({ t: DNAMES[k] || k, n: '', card: true, render: () => DIALOGS[k]() }))],
  ['extension', 'Browser extension', 'The Larsal extension for Chrome, Safari, Firefox, Edge and Brave (E7-S7). It stores nothing: every fill is a request to Larsal on this Mac. Shown in Chrome.', EXT_FRAMES],
  ['menubar', 'Menu bar and floating panels', 'The menu bar icon (S-UI-10) and the Auto-Type picker that appears over other apps.', [
    { t: 'Menu bar icon', n: 'Lock state of every vault', w: 720, h: 420, render: menuBarWin },
    { t: 'Auto-Type picker', n: 'Appears over the browser', w: 720, h: 420, render: autotypePicker },
  ]],
];
const FR = [];
let THEME = 'light', ZOOM = 'fit';
function frameHtml(i) {
  const f = FR[i], theme = f.theme || THEME, w = f.w || W, h = f.h || H;
  const inner = f.render ? f.render(f.s || {}) : shell(f.s);
  const z = ZOOM === 'fit' ? Math.min(1, (document.getElementById('board').clientWidth - 8) / w) : +ZOOM;
  return f.card ? `<div class="zoom" style="--z:${z}"><div class="win cardwin ${theme}" data-f="${i}" style="overflow:visible;box-shadow:none">${inner}</div></div>`
    : `<div class="zoom" style="--z:${z}"><div class="win ${theme}" data-f="${i}" style="width:${w}px;height:${h}px">${inner}</div></div>`;
}
function renderBoard() {
  FR.length = 0;
  const board = document.getElementById('board');
  board.innerHTML = SECTIONS.map(([id, title, note, frames]) => `<section class="bsec" id="${id}"><h2>${title}</h2><p>${note}</p><div class="frames">${frames.map((f) => { const fid = id + '-' + slug(f.t); const i = FR.push({ ...f, id: fid, sec: id, s: f.s ? JSON.parse(JSON.stringify(f.s)) : null }) - 1; return `<figure class="frame" id="${fid}" data-fi="${i}"></figure>`; }).join('')}</div></section>`).join('');
  document.getElementById('index').innerHTML = SECTIONS.map(([id, t]) => `<a href="#${id}">${t}</a>`).join('');
  board.querySelectorAll('.frame').forEach((el) => { const i = +el.dataset.fi; el.innerHTML = frameHtml(i) + `<figcaption><b>${FR[i].t}</b>${FR[i].n ? ` <span>· ${FR[i].n}</span>` : ''}</figcaption>`; });
  tick();
}
const slug = (t) => t.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
// Manifest for the build and verify fleet: one record per frame with every visible string and accessible name.
window.MOCKUP_MANIFEST = () => FR.map((f, i) => { const w = document.querySelector(`.win[data-f="${i}"]`);
  const texts = [...new Set(w.innerText.split('\n').map((t) => t.trim()).filter(Boolean))];
  const names = [...new Set([...w.querySelectorAll('[aria-label]')].map((n) => n.getAttribute('aria-label')))];
  const placeholders = [...new Set([...w.querySelectorAll('[placeholder]')].map((n) => n.getAttribute('placeholder')).filter(Boolean))];
  return { id: f.id, section: f.sec, title: f.t, note: f.n || '', width: f.w || (f.card ? null : W), height: f.h || (f.card ? null : H), texts, accessibleNames: names, placeholders }; });
function rerender(i) {
  const fig = document.querySelector(`.frame[data-fi="${i}"]`);
  fig.querySelector('.zoom').outerHTML = frameHtml(i);
  tick();
}

// ---------- live codes ----------
let lastStep = step();
function tick() {
  const now = clock(), st = step(), left = 30 - Math.floor((now / 1000) % 30), ratio = ((now / 1000) % 30) / 30;
  if (st !== lastStep) { lastStep = st; document.querySelectorAll('[data-totp]').forEach((n) => { n.textContent = fmtCode(code(n.dataset.totp, st)); }); }
  document.querySelectorAll('[data-tick]').forEach((n) => { n.style.transform = `scaleX(${1 - ratio})`; });
  document.querySelectorAll('[data-secs]').forEach((n) => { n.textContent = `New code in ${left} s`; });
  document.querySelectorAll('[data-secs-short]').forEach((n) => { n.textContent = left + ' s'; });
}
setInterval(tick, 250);

// ---------- interaction ----------
const toastTimers = {};
function act(i, a, v, el) {
  const s = FR[i].s; if (!s) return;
  const close = () => { s.overlay = null; };
  switch (a) {
    case 'view': Object.assign(s, { view: v, tab: 'all', reveal: false, overlay: null, mode: v === 'health' ? 'reports' : 'list', rep: 'health' }); break;
    case 'tab': s.tab = v; break;
    case 'sel': s.sel = v; s.reveal = false; close(); break;
    case 'reveal': s.reveal = !s.reveal; break;
    case 'menu': s.overlay = s.overlay === v ? null : v; break;
    case 'sort': s.sort = v; close(); break;
    case 'tags': s.tagsOpen = !s.tagsOpen; break;
    case 'lock': s.mode = 'locked'; s.unlock = null; s.err = false; close(); break;
    case 'unlock': s.mode = 'list'; close(); break;
    case 'unlockmode': s.unlock = v; s.err = false; break;
    case 'edit': s.mode = 'editor'; s.page = 'entry'; s.edit = s.sel; s.isNew = false; close(); break;
    case 'editpage': s.mode = 'editor'; s.page = v; s.edit = s.sel; break;
    case 'new': s.mode = 'editor'; s.page = 'entry'; s.isNew = true; close(); break;
    case 'cancel': s.mode = 'list'; s.isNew = false; break;
    case 'save': s.mode = 'list'; s.isNew = false; s.toast = `${ic('check')}Saved <small>· Personal.larsalvault</small>`; break;
    case 'mode': s.mode = v; s.view = 'health'; s.rep = 'health'; break;
    case 'page': case 'spage': s.page = v; break;
    case 'rep': s.rep = v; break;
    case 'dialog': if (DIALOGS[v]) s.dialog = v; close(); break;
    case 'dclose': s.dialog = null; break;
    case 'clearq': s.q = ''; break;
    case 'gmode': s.gmode = v; break;
    case 'regen': s.seed = (s.seed || 0) + 1; break;
    case 'gset': s.gsets = s.gsets || { upper: true, lower: true, digits: true, symbols: true }; s.gsets[v] = !s.gsets[v]; if (!Object.values(s.gsets).some(Boolean)) s.gsets[v] = true; break;
    case 'settings': s.toast = `${ic('gear-six')}Settings open in their own window <small>· see the Settings section</small>`; break;
    case 'copy': s.toast = { username: `${ic('check')}Username copied`, password: `${ic('check')}Password copied <small>· clipboard clears in 30 s</small>`, code: `${ic('check')}One-time code copied <small>· clears in 30 s</small>`, open: `${ic('arrow-square-out')}Opens in your browser`, type: `${ic('keyboard')}Types the login into the window behind Larsal`, agent: `${ic('check')}Key loaded into the SSH agent`, restore: `${ic('check')}Restored to Social`, generated: `${ic('check')}Password copied <small>· clears in 30 s</small>`, number: `${ic('check')}Card number copied`, fingerprint: `${ic('check')}Fingerprint copied` }[v] || `${ic('check')}Copied`; close(); break;
    default: return;
  }
  if (a === 'copy' || a === 'save' || a === 'settings') { clearTimeout(toastTimers[i]); toastTimers[i] = setTimeout(() => { s.toast = null; rerender(i); }, 2600); }
  rerender(i);
}
document.addEventListener('click', (ev) => {
  const tb = ev.target.closest('[data-board-theme]'), zb = ev.target.closest('[data-board-zoom]');
  if (tb) { THEME = tb.dataset.boardTheme; document.body.classList.toggle('b-dark', THEME === 'dark'); document.querySelectorAll('[data-board-theme]').forEach((b) => b.setAttribute('aria-pressed', b === tb)); renderBoard(); return; }
  if (zb) { ZOOM = zb.dataset.boardZoom; document.querySelectorAll('[data-board-zoom]').forEach((b) => b.setAttribute('aria-pressed', b === zb)); renderBoard(); return; }
  const win = ev.target.closest('.win[data-f]'); if (!win) return;
  const i = +win.dataset.f, el = ev.target.closest('[data-a]');
  if (ev.target.closest('a[href="#"]')) ev.preventDefault();
  if (el && ['sw', 'cbx'].includes(el.dataset.a)) { const t = el.dataset.a === 'sw' ? el : el.querySelector('.cb'); t.setAttribute('aria-checked', t.getAttribute('aria-checked') !== 'true'); return; }
  if (el && el.tagName !== 'INPUT') { act(i, el.dataset.a, el.dataset.v, el); return; }
  const s = FR[i].s; if (s && s.overlay && !ev.target.closest('.menu, .gen, .tips')) { s.overlay = null; rerender(i); }
});
document.addEventListener('focusin', (ev) => {
  const inpEl = ev.target.closest('input[data-a="q"]'); if (!inpEl) return;
  const i = +inpEl.closest('.win').dataset.f, s = FR[i].s;
  if (s && !s.q && s.overlay !== 'tips') { s.overlay = 'tips'; rerender(i); const n = document.querySelector(`.win[data-f="${i}"] input[data-a="q"]`); n.focus(); }
});
document.addEventListener('input', (ev) => {
  const t = ev.target, win = t.closest('.win[data-f]'); if (!win) return;
  const i = +win.dataset.f, s = FR[i].s; if (!s) return;
  if (t.dataset.a === 'q') { s.q = t.value; s.overlay = s.q ? null : 'tips'; rerender(i); const n = document.querySelector(`.win[data-f="${i}"] input[data-a="q"]`); n.focus(); n.setSelectionRange(n.value.length, n.value.length); }
  if (t.dataset.a === 'glen') { s.glen = +t.value; rerender(i); document.querySelector(`.win[data-f="${i}"] input[data-a="glen"]`).focus(); }
  if (t.dataset.a === 'gwords') { s.gwords = +t.value; rerender(i); document.querySelector(`.win[data-f="${i}"] input[data-a="gwords"]`).focus(); }
});
document.addEventListener('keydown', (ev) => {
  if (!['ArrowDown', 'ArrowUp'].includes(ev.key) || ev.target.tagName === 'INPUT') return;
  const win = ev.target.closest && ev.target.closest('.win[data-f]'); if (!win) return;
  const i = +win.dataset.f, s = FR[i].s; if (!s || s.mode !== 'list') return;
  const list = visible(s), k = list.findIndex((e) => e.id === s.sel), n = list[k + (ev.key === 'ArrowDown' ? 1 : -1)];
  if (n) { ev.preventDefault(); s.sel = n.id; s.reveal = false; rerender(i); const w = document.querySelector(`.win[data-f="${i}"]`); w.querySelector(`[data-v="${n.id}"]`).focus(); }
});
window.addEventListener('resize', () => { if (ZOOM === 'fit' && document.getElementById('board')) renderBoard(); });

// ?only=<section> renders one section, &theme=dark for screenshots
const params = new URLSearchParams(location.search);
if (params.get('theme') === 'dark') { THEME = 'dark'; document.body.classList.add('b-dark'); document.querySelectorAll('[data-board-theme]').forEach((b) => b.setAttribute('aria-pressed', b.dataset.boardTheme === 'dark')); }
if (params.get('zoom')) { ZOOM = params.get('zoom'); }
if (params.get('only')) { const keep = params.get('only').split(','); for (let k = SECTIONS.length - 1; k >= 0; k--) if (!keep.includes(SECTIONS[k][0])) SECTIONS.splice(k, 1); }
document.head.insertAdjacentHTML('beforeend', '<style>.win.dark .logo path.dk{fill:var(--text)}</style>');
console.assert(attention().length === 6, 'needs-attention count is 6');
console.assert(attention().filter((e) => check(e).issue === 'Reused').length === 2, 'two reused');
if (document.getElementById('board')) renderBoard(); // the website loads this file for its app fragments
