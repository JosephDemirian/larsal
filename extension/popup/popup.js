// The toolbar popup's first frames (INT-11.23 to INT-11.26; story E7-S7d):
// not reachable, first connection, vault locked, and the no-vault line.
//
// The popup keeps no state of its own: each read asks the background for the
// state (`popup.status`) and draws the one frame `choose` gives (state.js). It
// reads again on each `{"notice":"state"}` from the background (INT-11.8's
// pace while Larsal answers 44 or 45, and Larsal's notices, INT-11.10), after
// each of its own requests is answered, and when a session ended, so the
// frame changes without a reload. It holds a "page" port while open.
//
// Words (INT-11.22): every text and accessible name is a message of
// _locales/en/messages.json, set with textContent or setAttribute only; vault
// names, the pairing words and Larsal's version are data, set the same way.

import { choose } from './state.js';

globalThis.browser ??= chrome;

const BROWSER = 'Chrome';
const MINIMUM = '133'; // INT-11 "Minimum browser versions": the Chrome build's minimum_chrome_version
const OPEN = 'app.larsal.desktop://open'; // D-INT11-1 (a)
const $ = (id) => document.getElementById(id);
const say = (id, ...subs) => browser.i18n.getMessage(id, subs);
const send = (route) => browser.runtime.sendMessage({ route }).catch(() => ({ error: 'not-reachable' }));

let pairing = false; // this popup's `connect` waits for its reply
let unlockRefused = false; // Larsal answered `unlock` with error 1 (INT-11.26)
let reading = null; // the state read in flight
let stale = false; // a notice came during it: read once more

/** The state reply of the background, with `last_app_version` (INT-11.24's MI11-04). */
async function read() {
  const [state, kept] = await Promise.all([
    send('popup.status'),
    browser.storage.local.get('last_app_version').catch(() => ({})),
  ]);
  return { ...state, last: kept.last_app_version };
}

/** Reads the state and draws its frame; a read asked for during another one runs after it. */
function refresh() {
  if (reading) {
    stale = true;
    return reading;
  }
  reading = read()
    .then(draw)
    .finally(() => {
      reading = null;
      if (stale) {
        stale = false;
        refresh();
      }
    });
  return reading;
}

function show(frame) {
  for (const el of document.querySelectorAll('[data-frame]')) el.hidden = el.dataset.frame !== frame;
  document.body.dataset.shown = frame;
}

function draw(state) {
  const view = choose(state);
  if (view.frame === 'again') return void refresh();
  if (view.frame !== 'locked') unlockRefused = false;
  show(view.frame);
  if (view.frame === 'not-reachable') notReachable(view, state.last);
  else if (view.frame === 'locked') locked(view);
  else if (view.frame === 'first-connection') firstConnection(view);
}

/** INT-11.24, and INT-11.5's MI11-60 when the browser is too old. */
function notReachable(view, last) {
  $('reach-text').textContent = view.tooOld ? say('MI11_60', BROWSER, MINIMUM) : say('MI11_02');
  $('checks').hidden = $('reach-buttons').hidden = Boolean(view.tooOld);
  if (view.tooOld) return;
  view.marks.forEach((mark, i) => {
    $(`mark-${i}`).className = `ph-fill mark ${mark}`;
    $(`mark-${i}`).dataset.mark = mark;
  });
  $('hint-0').textContent = typeof last === 'string' && last ? say('MI11_04', last) : say('MI11_04_b', BROWSER);
  $('check-2').textContent = say('MI11_07', BROWSER);
}

/** INT-11.26: the shown vault's name; the other open vaults, a line with no action (D-INT11-3). */
function locked(view) {
  $('locked-title').textContent = say('MI11_15', view.vault);
  $('others').hidden = !view.others.length;
  $('others-text').textContent = say('MI11_20', view.others.join(', '));
  $('unlock-refused').hidden = !unlockRefused;
  $('unlock-refused').textContent = say('MI11_103', view.vault);
}

/**
 * INT-11.25: the words of the session the `connect` goes on, and one `connect` while none waits;
 * after Larsal's Deny, MI11-61 with Try Again in place of a new one.
 */
function firstConnection(view) {
  $('connect-title').textContent = say('MI11_11', BROWSER);
  const spans = $('words').children;
  for (let i = 0; i < spans.length; i++) spans[i].textContent = view.words[i] ?? '';
  $('refused').hidden = !view.refused;
  $('waiting').hidden = view.refused;
  if (!view.refused && !view.connecting && !pairing) connect();
}

async function connect() {
  pairing = true;
  const reply = send('popup.connect');
  refresh(); // after the connect in the background's order: MI11-13 in place of MI11-61 at once
  await reply;
  pairing = false;
  refresh();
}

/** Every fixed text and accessible name, from its message (INT-11.22). */
function words() {
  document.title = say('MI11_101_a');
  for (const el of document.querySelectorAll('[data-msg]')) el.textContent = say(el.dataset.msg);
  for (const el of document.querySelectorAll('[data-label]')) el.setAttribute('aria-label', say(el.dataset.label));
}

words();
$('try').addEventListener('click', () => refresh()); // MI11-09: a new hello now
$('again').addEventListener('click', () => connect());
$('cancel').addEventListener('click', () => {
  // INT-11.25: the background ends the session and says hello again; the popup closes.
  send('popup.cancel');
  window.close();
});
$('unlock').addEventListener('click', async () => {
  // B8: `unlock` and nothing else; Larsal shows its own unlock panel.
  const reply = await send('popup.unlock');
  unlockRefused = reply?.error === 1;
  refresh();
});
for (const open of document.querySelectorAll('.open')) {
  // MI11-10, D-INT11-1 (a): Larsal's one URL, which only brings Larsal to the front; the browser asks first.
  open.addEventListener('click', () => browser.tabs.create({ url: OPEN }).catch(() => {}));
}
browser.runtime.onMessage.addListener((message, sender) => {
  // Only this extension's background (no tab) tells the popup to read the state again.
  if (sender?.id === browser.runtime.id && !sender.tab && message?.notice === 'state') refresh();
});
browser.runtime.connect({ name: 'page' }); // INT-11.8: the background paces hellos while it is open
refresh();
