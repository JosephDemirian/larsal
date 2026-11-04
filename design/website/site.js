'use strict';
/* Website behaviour: navigation, the hero demo, the sky, the logo strip, the app screens in every card,
   carousels, the FAQ and the reveals. App screens are drawn by ../option-a/mockup.js, so the site always
   shows the locked Option A design. Everything stays readable with scripts off. */

ZOOM = '1';
THEME = 'dark';
const q1 = (s, r = document) => r.querySelector(s);
const qa = (s, r = document) => [...r.querySelectorAll(s)];
const calm = matchMedia('(prefers-reduced-motion: reduce)').matches;
const noH1 = (html) => html.replace(/<h1>/g, '<div class="h1">').replace(/<\/h1>/g, '</div>'); // the page keeps the only h1
const mono = (key, size) => { const b = window.BRANDS[key]; return b ? `<svg viewBox="0 0 24 24" aria-hidden="true"${size ? ` width="${size}" height="${size}"` : ''}><path fill="currentColor" d="${b.path}"/></svg>` : ''; };
const mark = (k, size) => k.startsWith('ph:') ? `<i class="ph ph-${k.slice(3)}" aria-hidden="true"></i>` : mono(k, size);
const seeded = (n) => { let h = n; return () => { h = (Math.imul(h ^ (h >>> 15), 2246822507) + 0x9e3779b9) >>> 0; return h / 4294967296; }; };

// ---------- navigation ----------
const nav = q1('#nav');
const onScroll = () => nav.classList.toggle('scrolled', scrollY > 8);
addEventListener('scroll', onScroll, { passive: true });
onScroll();
const PRODUCT = [
  ['vault', 'Vault', '--blue', 'tray', 'Groups, logos, health and history'],
  ['extension', 'Browser Extension', '--teal', 'globe-simple', 'Sign-ins, codes and passkeys'],
  ['security-model', 'Security', '--purple', 'lock-key', 'How encryption works'],
  ['developers', 'For Developers', '--graphite', 'terminal-window', 'SSH agent, Auto-Type, imports'],
];
q1('#ddpanel').innerHTML = PRODUCT.map(([id, t, c, i, d]) => `<a href="#${id}">${tile(c, i, 'md')}<span><b>${t}</b><small>${d}</small></span></a>`).join('');
const dd = q1('#dd'), ddBtn = q1('#dd > button'), hoverable = matchMedia('(hover: hover) and (pointer: fine)');
const setDD = (open) => { dd.classList.toggle('open', open); ddBtn.setAttribute('aria-expanded', open); };
ddBtn.addEventListener('click', () => setDD(!dd.classList.contains('open')));
dd.addEventListener('mouseenter', () => { if (hoverable.matches) setDD(true); });
dd.addEventListener('mouseleave', () => { if (hoverable.matches) setDD(false); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { setDD(false); closeMenu(); } });
document.addEventListener('click', (e) => { if (!dd.contains(e.target)) setDD(false); });
const menuBtn = q1('#menuBtn');
function closeMenu() { nav.classList.remove('menu-open'); menuBtn.setAttribute('aria-expanded', false); menuBtn.setAttribute('aria-label', 'Open menu'); menuBtn.innerHTML = '<i class="ph ph-list" aria-hidden="true"></i>'; }
menuBtn.addEventListener('click', () => {
  const open = !nav.classList.contains('menu-open');
  nav.classList.toggle('menu-open', open); menuBtn.setAttribute('aria-expanded', open);
  menuBtn.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
  menuBtn.innerHTML = `<i class="ph ph-${open ? 'x' : 'list'}" aria-hidden="true"></i>`;
});
qa('.links a').forEach((a) => a.addEventListener('click', () => { setDD(false); closeMenu(); }));
q1('#ghMark').innerHTML = `<path fill="currentColor" d="${window.BRANDS.github.path}"/>`;
q1('#socGh').innerHTML = mono('github', 17);
q1('#socMa').innerHTML = mono('mastodon', 17);

// ---------- sky: rays and arches behind the hero, the floor grid under the closing panel, stars ----------
(() => {
  const W = 1680, cx = 840, vy = 600;
  let h = '<defs><radialGradient id="skyfade" cx="50%" cy="62%" r="60%"><stop offset="0" stop-color="#fff" stop-opacity="1"/><stop offset=".75" stop-color="#fff" stop-opacity=".35"/><stop offset="1" stop-color="#fff" stop-opacity="0"/></radialGradient><mask id="skymask"><rect width="1680" height="900" fill="url(#skyfade)"/></mask></defs><g mask="url(#skymask)">';
  for (let k = 0; k <= 26; k++) { const x = -260 + (k / 26) * (W + 520); h += `<line x1="${x.toFixed(1)}" y1="0" x2="${cx}" y2="${vy}" stroke="rgba(255,255,255,.05)"/>`; }
  for (let k = 0; k < 6; k++) {
    const w = 560 + k * 200, top = 96 + k * 26, r = 140 + k * 26, x0 = cx - w / 2, x1 = cx + w / 2;
    h += `<path d="M ${x0} 900 L ${x0} ${top + r} Q ${x0} ${top} ${x0 + r} ${top} L ${x1 - r} ${top} Q ${x1} ${top} ${x1} ${top + r} L ${x1} 900" fill="none" stroke="rgba(255,255,255,${(0.085 - k * 0.011).toFixed(3)})"/>`;
  }
  q1('#sky').innerHTML = h + '</g>';
  let g = '<defs><linearGradient id="floorfade" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#fff" stop-opacity="0"/><stop offset="1" stop-color="#fff" stop-opacity="1"/></linearGradient><mask id="floormask"><rect width="1200" height="240" fill="url(#floorfade)"/></mask></defs><g mask="url(#floormask)" stroke="rgba(155,230,242,.22)">';
  for (let k = -12; k <= 12; k++) g += `<line x1="${600 + k * 34}" y1="0" x2="${600 + k * 150}" y2="240"/>`;
  for (let k = 1; k <= 7; k++) { const y = 240 * Math.pow(k / 7, 1.8); g += `<line x1="0" y1="${y.toFixed(1)}" x2="1200" y2="${y.toFixed(1)}"/>`; }
  q1('#floorGrid').innerHTML = g + '</g>';
  qa('[data-stars]').forEach((box, n) => {
    const r = seeded(17 + n * 101), count = +box.dataset.stars;
    box.innerHTML = Array.from({ length: count }, () => `<i style="left:${(r() * 100).toFixed(2)}%;top:${(r() * 100).toFixed(2)}%;--o:${(0.12 + r() * 0.5).toFixed(2)};--d:${(3 + r() * 5).toFixed(1)}s;--dl:${(-r() * 6).toFixed(1)}s${r() > 0.85 ? ';width:3px;height:3px' : ''}"></i>`).join('');
  });
})();

// ---------- hero demo: real app screens played like a video; nothing in it can be clicked ----------
const stage = q1('#stage'), cam = q1('#cam');
cam.inert = true; // the demo is a picture: no focus, no clicks, hidden from assistive tech (the wrapper carries the label)
const demo = { play: !calm, visible: true, clock: 0, selTop: null, scale: 0.9, phone: false, focusX: 380 };
let win = null;
const waiters = [];
const sleep = (ms) => new Promise((res) => waiters.push({ until: demo.clock + ms, res })); // play-time sleep: it stops while paused
const playing = () => demo.play && demo.visible && !document.hidden;

// one frame of the app; how: 'none' (typing, popovers), 'sheet' (a page change inside the window), 'fade' (the whole window)
function frame(state, how = 'none') {
  const old = win && win.querySelector('.sheet');
  const ghost = how === 'sheet' && old ? old.cloneNode(true) : null;
  if (!win) { win = document.createElement('div'); win.className = 'win dark'; win.style.cssText = 'width:1320px;height:820px'; cam.appendChild(win); }
  win.innerHTML = noH1(shell(state));
  slideSelection(how === 'sheet' || how === 'none');
  const fresh = win.querySelector('.sheet');
  if (ghost && fresh) {
    ghost.classList.add('ghost');
    Object.assign(ghost.style, { left: `${fresh.offsetLeft}px`, top: `${fresh.offsetTop}px`, width: `${fresh.offsetWidth}px`, height: `${fresh.offsetHeight}px`, margin: '0' });
    win.appendChild(ghost); fresh.classList.add('enter');
    setTimeout(() => ghost.remove(), 460);
  }
  tick();
}
async function show(state, how) {
  // a whole-window change crossfades: the old picture fades out over the new one
  const ghost = how === 'fade' && win ? win.cloneNode(true) : null;
  frame(state, how);
  if (ghost) { ghost.classList.add('wghost'); cam.appendChild(ghost); setTimeout(() => ghost.remove(), 480); }
  await sleep(10);
}
// the sidebar's selected row slides from the old item to the new one, as in the reference demo
function slideSelection(animate) {
  const sb = win.querySelector('.sb'), cur = sb && sb.querySelector('.si[aria-current="page"]');
  if (!cur) { demo.selTop = null; return; }
  const sel = document.createElement('span'), top = cur.offsetTop;
  sel.className = 'sel';
  sel.style.cssText = `left:${cur.offsetLeft}px;width:${cur.offsetWidth}px;height:${cur.offsetHeight}px;top:${animate && demo.selTop != null ? demo.selTop : top}px`;
  sb.prepend(sel);
  if (animate && demo.selTop != null && demo.selTop !== top) { sel.getBoundingClientRect(); sel.style.top = `${top}px`; }
  demo.selTop = top;
}
// where an element sits in window pixels
function spot(selector) {
  const el = win && win.querySelector(selector); if (!el) return null;
  const r = el.getBoundingClientRect(), c = cam.getBoundingClientRect();
  return { el, x: (r.left + r.width / 2 - c.left) / demo.scale, y: (r.top + r.height / 2 - c.top) / demo.scale };
}
function aim(x) {
  demo.focusX = x;
  if (!demo.phone) { cam.style.transform = ''; return; }
  const view = stage.clientWidth / demo.scale;
  cam.style.transform = `translateX(${Math.max(Math.min(0, view / 2 - x), view - 1320)}px)`;
}
async function press(selector) {
  const p = spot(selector); if (!p) return;
  aim(p.x);
  if (demo.phone) await sleep(560);
  const ring = document.createElement('span');
  ring.className = 'press'; ring.style.left = `${p.x}px`; ring.style.top = `${p.y}px`;
  cam.appendChild(ring); setTimeout(() => ring.remove(), 760);
  p.el.classList.add('pressed'); setTimeout(() => p.el.classList.remove('pressed'), 180);
  await sleep(220);
}
const typing = () => { const s = win.querySelector('.tb .search'); if (s) s.classList.add('typing'); };
const flash = () => { const o = win.querySelector('.gen .out'); if (o) o.classList.add('flash'); };

// the demo is one continuous take of about 15 seconds that starts over, like a short film
async function take() {
  // find a login
  frame(M({})); aim(380); await sleep(500);
  await press('.tb .search');
  for (const q of ['a', 'am', 'ama']) { frame(M({ q })); typing(); await sleep(150); }
  await sleep(200);
  await press('.row[data-v="amazon"]');
  frame(M({ q: 'ama', sel: 'amazon' })); typing(); aim(1080); await sleep(1200);
  // password health
  frame(M({})); aim(380); await sleep(120);
  await press('.si[data-v="health"]');
  frame(M({ mode: 'reports', view: 'health', rep: 'health' }), 'sheet'); aim(700); await sleep(1300);
  // two-step codes
  await press('.si[data-v="codes"]');
  frame(M({ view: 'codes', sel: 'google' }), 'sheet'); await sleep(700);
  await press('.rail [data-a="copy"][data-v="code"]');
  frame(M({ view: 'codes', sel: 'google', toast: `${ic('check')}One-time code copied <small>· clears in 30&nbsp;s</small>` })); aim(800); await sleep(1200);
  // strong passwords
  frame(M({ view: 'codes', sel: 'google' })); await sleep(120);
  await press('[data-a="menu"][data-v="gen"]');
  frame(M({ view: 'codes', sel: 'google', overlay: 'gen', seed: 1 })); await sleep(700);
  for (const seed of [2, 3]) { await press('.gen [data-a="regen"]'); frame(M({ view: 'codes', sel: 'google', overlay: 'gen', seed })); flash(); await sleep(550); }
  // passkeys and SSH keys
  frame(M({ view: 'codes', sel: 'google' })); aim(380); await sleep(120);
  await press('.si[data-v="passkeys"]');
  frame(M({ view: 'passkeys', sel: 'apple' }), 'sheet'); aim(1080); await sleep(1100);
  aim(380); await sleep(200);
  await press('.si[data-v="servers"]');
  frame(M({ view: 'servers', sel: 'web01' }), 'sheet'); aim(1080); await sleep(1200);
  // lock, then unlock with Touch ID
  await press('.tb [data-a="lock"]');
  await show(M({ mode: 'locked' }), 'fade'); aim(660); await sleep(900);
  await press('.touch'); await sleep(200);
  await show(M({}), 'fade'); aim(380); await sleep(600);
}
async function runDemo() { for (;;) await take(); }
let lastT = performance.now();
function loop(t) {
  const dt = Math.min(t - lastT, 100); lastT = t;
  if (playing()) {
    demo.clock += dt;
    for (let i = waiters.length - 1; i >= 0; i--) if (demo.clock >= waiters[i].until) waiters.splice(i, 1)[0].res();
  }
  requestAnimationFrame(loop);
}
const toggle = q1('#demoToggle');
function setPlay(on) {
  demo.play = on;
  document.documentElement.classList.toggle('motion-paused', !on); // the demo, the logo strip, stars and glows all stop together
  toggle.setAttribute('aria-label', on ? 'Pause animations' : 'Play animations');
  toggle.innerHTML = `<i class="ph-fill ph-${on ? 'pause' : 'play'}" aria-hidden="true"></i>`;
}
toggle.addEventListener('click', () => setPlay(!demo.play));
new IntersectionObserver((es) => es.forEach((e) => { demo.visible = e.isIntersecting; }), { threshold: 0.15 }).observe(stage);
function fitDemo() {
  demo.phone = innerWidth <= 640;
  demo.scale = demo.phone ? stage.clientWidth / 760 : Math.min(0.92, stage.clientWidth / 1320);
  stage.style.setProperty('--s', demo.scale.toFixed(4));
  stage.style.setProperty('--stage-h', `${Math.round(820 * demo.scale * (demo.phone ? 0.8 : 0.78))}px`);
  aim(demo.focusX);
}

// ---------- logo strip ----------
(() => {
  const LOGOS = [['safari', 'Safari'], ['googlechrome', 'Chrome'], ['firefoxbrowser', 'Firefox'], ['brave', 'Brave'], ['opera', 'Opera'], ['vivaldi', 'Vivaldi'], ['icloud', 'iCloud Drive'], ['dropbox', 'Dropbox'], ['yubico', 'YubiKey'], ['ph-fill:fingerprint', 'Touch ID']];
  const one = (aria) => LOGOS.map(([k, n]) => `<span class="item"${aria ? ' aria-hidden="true"' : ''}>${k.startsWith('ph-fill:') ? `<i class="ph-fill ph-${k.slice(8)}" aria-hidden="true"></i>` : mono(k)}${n}</span>`).join('');
  q1('#marquee').innerHTML = one(false) + one(true);
})();

// ---------- pieces of the app, shown on their own ----------
// Each card shows one part of the app (a list, a detail panel, a popup, a dialog) whole, with no window around it.
// The markup comes from ../option-a/mockup.js, so every piece is the locked design. Pieces are pictures: inert.
const dom = (html) => { const t = document.createElement('template'); t.innerHTML = noH1(html); return t.content; };
const box = (html) => dom(`<div>${html}</div>`).firstElementChild;
const cut = (root, sel) => root.querySelectorAll(sel).forEach((el) => el.remove());
const drop = (el, n) => [...el.children].forEach((c, i, all) => { if (n(i, all.length)) c.remove(); }); // removes the children n() names
const out = (el) => el.outerHTML;
// w: the piece's width in app pixels; h: its height when a menu hangs below it; pw: a narrower width it reflows to
// on phones, where shrinking a wide piece would make its text too small to read. fitPieces then scales it to fit.
const piece = (html, w, h = 0, pw = 0) => `<div class="piece" data-ui inert><div class="win dark comp" data-w="${w}"${pw ? ` data-pw="${pw}"` : ''} style="width:${w}px${h ? `;height:${h}px` : ''}">${noH1(html)}</div></div>`;
function fitPieces() {
  qa('.piece').forEach((p) => {
    const c = p.firstElementChild, room = p.clientWidth - 48, narrow = !!c.dataset.pw && room / c.dataset.w < 0.8;
    p.classList.toggle('narrow', narrow);
    c.style.width = `${narrow ? c.dataset.pw : c.dataset.w}px`;
    const fitW = Math.min(1, room / c.offsetWidth), fitH = (p.clientHeight - 48) / c.offsetHeight;
    const s = fitH < fitW && fitH >= fitW * 0.86 && fitH >= 0.8 ? fitH : fitW; // shrink a little to show it whole, never much
    c.style.setProperty('--ps', s.toFixed(3));
    p.classList.toggle('tall', c.offsetHeight * s > p.clientHeight - 47); // still too tall: pin it to the top and fade out the bottom
  });
}
// the detail panel of one entry, without the parts a card does not need
function railPart(id, o, parts = '.panel + .panel, .rfoot', fields) {
  const r = box(rail(byId(id), M(o)));
  cut(r, parts);
  if (fields) drop(r.querySelector('.panel'), (i, n) => !fields(i, n)); // fields(i, n) names the fields to keep
  return r.innerHTML;
}
const TOAST = `${ic('check')}Password copied <small>· clipboard clears in 30&nbsp;s</small>`;
const P = {
  groups() {
    const sb = dom(sidebar(M({ view: 'social', tagsOpen: true }))), [, groups, tags] = sb.querySelectorAll('.sb > ul'), [hg, ht] = sb.querySelectorAll('.sb-h');
    return piece(`<div class="duo">${[[hg, groups], [ht, tags]].map(([h, ul]) => `<div class="cpanel sb sbp">${out(h)}${out(ul)}</div>`).join('')}</div>`, 540, 0, 300);
  },
  logos() {
    const s = M({ sort: 'title', sel: null });
    return piece(`<div class="cpanel lst"><div class="rows solo">${rows(s, visible(s).filter((e) => e.brand && !e.passkey).slice(0, 6))}</div></div>`, 302);
  },
  health: () => piece(`<div class="cpanel pad">${REPS.health()}</div>`, 760, 0, 340),
  card: () => piece(`<div class="cpanel pad">${railPart('visa', { view: 'banking', sel: 'visa' })}</div>`, 320),
  history: () => piece(`<div class="cpanel pad">${EDP.history(byId('github'))}</div>`, 640, 0, 340),
  popup: () => piece(out(dom(EXT.matches()).querySelector('.xp')), 302),
  field: () => piece(out(dom(EXT.inline()).querySelector('.sitecard')), 340, 292, 300),
  otp: () => piece(out(dom(EXT.otp()).querySelector('.sitecard')), 302, 176),
  save: () => piece(out(dom(EXT.save()).querySelector('.xprompt')), 380, 0, 320),
  passkey: () => piece(out(dom(EXT.passkeyUse()).querySelector('.xprompt')), 302),
  touch() {
    const u = dom(lockedWindow(M({ mode: 'locked' }))).querySelector('.ucard');
    cut(u, '.stack'); // the password button: this card is about Touch ID
    return piece(`<div class="cpanel pad lockp">${out(u)}</div>`, 420, 0, 330);
  },
  keys() {
    const u = dom(lockedWindow(M({ mode: 'locked', unlock: 'password', err: true }))).querySelector('.ucard');
    cut(u, '.tile.xl, .h1, .path, .uerr, .opts, .btn.primary'); // only the password and the two extra keys
    u.querySelectorAll('.bad').forEach((el) => el.classList.remove('bad'));
    return piece(`<div class="cpanel pad">${out(u)}</div>`, 302);
  },
  cipher() {
    const v = box(VSETP.security());
    return piece(`<div class="cpanel pad terse">${out(v.querySelectorAll('.grp')[1])}${out(v.querySelector('.help'))}</div>`, 600, 0, 360);
  },
  clipboard: () => piece(`<div class="stack-piece">${railPart('github', {}, '.rhead, .quick, .notice, .panel + .panel, .rfoot', (i) => i < 2)}<div class="toast" role="status">${TOAST}</div></div>`, 302),
  breach() {
    const r = box(REPS.breach());
    cut(r, 'table'); // the promise and the counts; the list of entries is the app's business
    return piece(`<div class="cpanel pad">${r.innerHTML}</div>`, 640, 0, 340);
  },
  ssh: () => piece(`<div class="cpanel pad">${railPart('web01', { view: 'servers', sel: 'web01', reveal: true }, '.notice, .panel + .panel, .rfoot', (i, n) => i >= n - 2)}</div>`, 440, 0, 350),
  approve: () => piece(DIALOGS.sshConfirm(), 302),
  importer: () => piece(DIALOGS.importDlg(), 560, 0, 360),
  menubar() {
    const m = dom(menuBarWin()), bar = m.querySelector('.mbar'), menu = m.querySelector('.menu');
    drop(bar, (i) => i < 7); // only the right end of the menu bar: App's icon, Wi-Fi and the clock
    menu.removeAttribute('style');
    return piece(`<div class="mbar-mini">${out(bar)}</div>${out(menu)}`, 302);
  },
  autotype() {
    const d = dom(autotypePicker()).querySelector('.dlg');
    ['position', 'top', 'left', 'transform', 'width'].forEach((k) => d.style.removeProperty(k));
    return piece(out(d), 540, 0, 330); // wide enough for the key help on one line
  },
};

// bento cards
q1('#bHealth').innerHTML = piece(`<div class="cpanel pad">${railPart('amazon', { tab: 'attention', sel: 'amazon' }, '.quick, .panel + .panel, .rfoot', (i) => i < 2)}</div>`, 380, 0, 350);
q1('#bCodes').innerHTML = (() => {
  const t = dom(listView(M({ view: 'codes', sort: 'title', sel: 'github' }))).querySelector('.tbl');
  t.querySelector('.rows').classList.add('solo');
  return piece(`<div class="cpanel">${out(t)}</div>`, 560, 0, 330);
})();
q1('#bList').innerHTML = (() => {
  const s = M({ q: 'posteo', sort: 'title', sel: 'paypal' }), t = dom(listView(s)).querySelector('.tbl');
  t.querySelector('.rows').classList.add('solo');
  return piece(`<div class="duo"><div class="cpanel" style="width:600px"><div class="searchrow">${searchBox(s)}</div>${out(t)}</div><div class="cpanel pad" style="width:380px">${rail(byId(s.sel), s)}</div></div>`, 1000, 0, 330);
})();

// product tours
const CARDS = {
  vault: [
    { w: 1, t: 'Colorful Groups and Tags', d: 'Sort entries into groups with their own color and icon, like folders in Finder. Tags cut across them.', p: 'groups' },
    { t: 'Real Logos for Every Site', d: 'Every entry shows its site’s logo from a set built into App, so nothing is fetched from the internet.', p: 'logos' },
    { w: 1, t: 'Built-In Password Health', d: 'Reused, weak and expired passwords surface on their own, with the fix one click away.', p: 'health' },
    { t: 'Cards, Wi-Fi and Notes', d: 'Card numbers, Wi-Fi networks and secure notes each get a layout made for them.', p: 'card' },
    { w: 1, t: 'Every Change, Kept', d: 'Earlier versions of each entry stay in the vault, so a bad edit is one click from undone.', p: 'history' },
  ],
  extension: [
    { t: 'Fill From the Toolbar', d: 'The App icon counts the logins it has for the site you are on. One click fills them in.', p: 'popup' },
    { w: 1, t: 'Fill From the Field', d: 'Pick a login right in the sign-in field. App fills it in and leaves the Sign In button to you.', p: 'field' },
    { t: 'Codes on the Next Step', d: 'When a site asks for a one-time code, App offers it, fresh every 30 seconds.', p: 'otp' },
    { w: 1, t: 'Saves New Sign-Ins', d: 'Sign up somewhere new and App offers to keep it, already sorted into a group.', p: 'save' },
    { t: 'Passkeys in the Browser', d: 'Sign in with a passkey from your vault. Touch ID in App confirms it.', p: 'passkey' },
  ],
  security: [
    { w: 1, t: 'Touch ID Unlock', d: 'Unlock with your fingerprint. While the vault is locked, App shows nothing from inside it, not even a title.', p: 'touch' },
    { t: 'Key Files and YubiKey', d: 'Add a key file or a hardware key, so a stolen password alone opens nothing.', p: 'keys' },
    { w: 1, t: 'AES-256 and Argon2id', d: 'Choose the cipher and how hard the key is to guess. The defaults follow current guidance.', p: 'cipher' },
    { t: 'A Clipboard That Forgets', d: 'Copied passwords and codes clear from the clipboard after 30 seconds.', p: 'clipboard' },
    { w: 1, t: 'Breach Checks Without Sharing', d: 'Find leaked passwords by sending only five characters of a hash. Your passwords never leave your Mac.', p: 'breach' },
  ],
  developers: [
    { w: 1, t: 'SSH Agent Built In', d: 'Keys load into the agent when the vault unlocks and leave again when it locks.', p: 'ssh' },
    { t: 'Approve Every Key Use', d: 'Ask before each signature, so no program uses a key behind your back.', p: 'approve' },
    { w: 1, t: 'Import From Other Managers', d: 'Bring logins over from Bitwarden, Proton Pass or a CSV file. App shows what it found first.', p: 'importer' },
    { t: 'Always in Your Menu Bar', d: 'See which vaults are open, lock everything or make a password without opening the window.', p: 'menubar' },
    { w: 1, t: 'Auto-Type Into Any App', d: 'Press ⌃⌥V in any window and App types the right login, even outside the browser.', p: 'autotype' },
  ],
};
const USES = {
  vault: ['Replaces', [['ph:table', 'Spreadsheets'], ['ph:note', 'Sticky Notes'], ['ph:browser', 'Browser Password Lists']]],
  extension: ['Works in', [['safari', 'Safari'], ['googlechrome', 'Chrome'], ['firefoxbrowser', 'Firefox'], ['brave', 'Brave'], ['opera', 'Opera'], ['vivaldi', 'Vivaldi']]],
  security: ['Built on', [['ph:lock-key', 'AES-256'], ['ph:lock-simple', 'ChaCha20'], ['ph:cpu', 'Argon2id'], ['ph:fingerprint', 'Touch ID'], ['yubico', 'YubiKey']]],
  developers: ['Imports from', [['bitwarden', 'Bitwarden'], ['protonmail', 'Proton Pass'], ['ph:file-csv', 'CSV Files']]],
};
qa('[data-cards]').forEach((track) => {
  track.innerHTML = CARDS[track.dataset.cards].map((c, i) => `<article class="pcard${c.w ? ' w' : ''}" data-r style="--i:${i % 3}"><div class="shot">${P[c.p]()}</div><div class="txt"><h3>${c.t}</h3><p>${c.d}</p></div></article>`).join('');
});
qa('[data-uses]').forEach((row) => {
  const [k, list] = USES[row.dataset.uses];
  row.innerHTML = `<span class="k">${k}</span>${list.map(([m, n]) => `<span>${mark(m, 17)}${n}</span>`).join('')}`;
});
qa('[data-tour]').forEach((sec) => {
  const track = q1('.track', sec), prev = q1('[data-prev]', sec), next = q1('[data-next]', sec);
  const step = () => q1('.pcard', track).getBoundingClientRect().width + 20;
  const sync = () => { prev.disabled = track.scrollLeft <= 2; next.disabled = track.scrollLeft + track.clientWidth >= track.scrollWidth - 2; };
  prev.addEventListener('click', () => track.scrollBy({ left: -step(), behavior: calm ? 'auto' : 'smooth' }));
  next.addEventListener('click', () => track.scrollBy({ left: step(), behavior: calm ? 'auto' : 'smooth' }));
  track.addEventListener('scroll', sync, { passive: true });
  addEventListener('resize', sync);
  sync();
});

// ---------- glowing card edges ----------
// "Glowing Effect" by Manu Arora (Aceternity UI), from 21st.dev component 1567, ported to plain JS. Each card's edge
// lights up in an arc that turns toward the pointer; cards within 64px of it light up too, so the glow runs from card
// to card. The browser animates the turn (a CSS transition on --start), as the component's animate() did.
const GLOW = { spread: 40, proximity: 64, inactiveZone: 0.01 };
const glows = qa('.bcard, .tcard, .pcard, .compare, .checks').map((card) => {
  const g = document.createElement('div');
  g.className = 'glowfx';
  card.appendChild(g);
  return { g, angle: 0 };
});
let pointer = null, glowFrame = 0;
function glowAll() {
  glowFrame = 0;
  if (!pointer) return;
  for (const it of glows) {
    const { left, top, width, height } = it.g.getBoundingClientRect(), cx = left + width / 2, cy = top + height / 2;
    const near = pointer.x > left - GLOW.proximity && pointer.x < left + width + GLOW.proximity && pointer.y > top - GLOW.proximity && pointer.y < top + height + GLOW.proximity;
    const on = near && Math.hypot(pointer.x - cx, pointer.y - cy) >= 0.5 * Math.min(width, height) * GLOW.inactiveZone;
    it.g.style.setProperty('--active', on ? 1 : 0);
    if (!on) continue;
    const target = (180 * Math.atan2(pointer.y - cy, pointer.x - cx)) / Math.PI + 90;
    it.angle += ((((target - it.angle + 180) % 360) + 360) % 360) - 180; // turn the short way round
    it.g.style.setProperty('--start', it.angle);
  }
}
const queueGlow = () => { if (!glowFrame) glowFrame = requestAnimationFrame(glowAll); };
if (hoverable.matches) { // a mouse or trackpad; touch screens have no pointer to follow
  document.body.addEventListener('pointermove', (e) => { pointer = { x: e.clientX, y: e.clientY }; queueGlow(); }, { passive: true });
  document.documentElement.addEventListener('pointerleave', () => { pointer = null; glows.forEach((it) => it.g.style.setProperty('--active', 0)); });
  addEventListener('scroll', queueGlow, { passive: true });
}

// ---------- FAQ ----------
const FAQ = [
  ['How much does App cost?', 'The Mac app is open source. Pricing for the planned hosted options isn’t set yet, and you can always build App from its source and run it yourself.'],
  ['Do I need an account?', 'No. The Mac app works without an account. A hosted sync option, if you choose one later, would use an account for syncing only.'],
  ['Where are my passwords stored?', 'In one encrypted file, such as Personal.appvault, on your Mac or wherever you put it. Today App sends nothing to any server.'],
  ['What happens if I forget my vault password?', 'Nobody can reset it, not even the people who make App; that is what keeps it safe. Write it down and keep it somewhere safe, and add Touch ID so you rarely type it.'],
  ['Can I import from my current password manager?', 'Yes. Import a CSV file or an export from Bitwarden or Proton Pass. App shows what it found before it changes anything.'],
  ['How do I sync between my Macs?', 'Keep the vault in iCloud Drive, Dropbox or any folder that syncs. If two Macs change it at the same time, App merges the changes. Sync through a server is planned.'],
  ['Can I host it myself?', 'That is the plan. We are designing a sync server you can run anywhere, and a hosted version for people who would rather not. Nothing is final yet, and the Mac app works without either.'],
  ['Is the browser extension safe?', 'The extension stores nothing. Each fill is a request to App on your Mac over an encrypted channel, and App asks before a site gets an entry for the first time.'],
  ['Does App work on iPhone or Windows?', 'Not yet; the Mac comes first. Your vault uses an open format, so apps that read that format can open it today.'],
  ['Has App been audited?', 'Not yet. The code is open, the security model is written down in plain words, and every part has tests anyone can run.'],
];
q1('#acc').innerHTML = FAQ.map(([qq, a], i) => `<div class="item" data-r style="--i:${i % 4}"><h3 style="margin:0"><button class="q" type="button" aria-expanded="false" aria-controls="faq-${i}" id="faq-q-${i}">${qq}<span class="plus" aria-hidden="true"></span></button></h3><div class="a" id="faq-${i}" role="region" aria-labelledby="faq-q-${i}"><div><p>${a}</p></div></div></div>`).join('');
const openFaq = (item, open) => { item.classList.toggle('open', open); q1('.q', item).setAttribute('aria-expanded', open); };
q1('#acc').addEventListener('click', (e) => { const b = e.target.closest('.q'); if (b) { const item = b.closest('.item'); openFaq(item, !item.classList.contains('open')); } });
qa('a[href="#faq"]').forEach((a) => { if (/hosting/i.test(a.textContent)) a.addEventListener('click', () => openFaq(qa('#acc .item')[6], true)); });

// ---------- start, reveal ----------
fitDemo();
fitPieces();
addEventListener('resize', () => { fitDemo(); fitPieces(); });
document.fonts.ready.then(fitPieces);
frame(M({}));
setPlay(!calm);
requestAnimationFrame(loop);
runDemo();
const seen = new IntersectionObserver((es) => es.forEach((e) => {
  if (!e.isIntersecting) return;
  e.target.classList.add('in');
  seen.unobserve(e.target);
}), { rootMargin: '0px 0px -10% 0px', threshold: 0.12 });
qa('[data-r]').forEach((el) => seen.observe(el));
