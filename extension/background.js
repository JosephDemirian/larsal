// Larsal's extension background (INT-11; story E7-S7c): one native messaging
// port to larsal-bridge (INT-11.8), the WebCrypto channel (INT-11.7), requests
// matched to their replies by `req` and nonce (INT-11.10), Larsal's notices
// (INT-01.46), and the routing table with its sender checks (INT-11.11,
// INT-11.12). Later stories each add one module and its row in ROUTES; E7-S7d
// adds the popup's first routes (status, connect, cancel, unlock) and the
// pairing words (words.js).
//
// What it holds (INT-11 "Parts"): the port; the session (its non-extractable
// keys, `sid` and requests in flight) until it ends (the port closes, a new
// hello, plain error 3, 4, 41, 44 or 45); the one `connect` and the one `unlock` in flight; the
// "page" ports of the open popup and options page (INT-11.8's pace); whether
// Larsal denied the last `connect` (INT-11.25). It keeps no reply: each need
// asks Larsal again. storage.local holds only `last_app_version`; the
// identification key lives in IndexedDB (idkey.js).

import * as channel from './channel.js';
import { identification } from './idkey.js';
import { classify } from './routes.js';
import { Requests, decode, encode, same } from './wire.js';
import { PAIRING, pairingWords } from './words.js';

globalThis.browser ??= chrome;

const HOST = 'app.larsal.browser';
const BROWSER = 'Chrome';
/** INT-11.10: the wait for a reply to a request that does not wait for the user, and for a hello's answer. */
const WAIT = 60_000;
/** INT-11.8: a reconnected port that closes this soon is not tried again until the next need. */
const QUICK = 1_000;
const SELF = { id: browser.runtime.id, origin: browser.runtime.getURL('').slice(0, -1) };
const text = new TextEncoder();

let link = null; // the open port: {port, hello, answer}, its hello in flight and that hello's answer
let reach = 'unknown'; // "ok", 44 (not running), 45 (integration off), "not-reachable" or "too-old"
let session = null;
let pairing = null; // the one `connect` in flight (INT-11.25)
let redo = false; // from a plain error 3 or 41 until the new hello's `check` ends (again)
let fours = false; // from a plain error 4 until the state read of its new hello ends (INT-11.10)
let refused = false; // Larsal denied the last `connect` (error 6), until the next one (INT-11.25)
let unlocking = null; // the one `unlock` in flight (INT-11.26)
let reached = false; // the last state read found Larsal reachable (the pages are told when it changes)
let list = null; // words.txt's lines, read once (INT-11.39)
const pages = new Set(); // the "page" ports of the open popup and options page (INT-11.8)
let pace = null; // the 1-second timer while a page is open
let pacing = null; // the state read of the last tick, while it runs

const fail = (why) => Object.assign(new Error(String(why)), { reach: why });
const quiet = (promise) => promise.catch(() => {});
/** INT-11.10: the popup and the options page read the state again. */
const tell = () => quiet(browser.runtime.sendMessage({ notice: 'state' }));

// INT-11.5: without X25519 in WebCrypto the background opens no port and sends nothing.
const capable = channel.keyPair().then(
  () => true,
  () => {
    reach = 'too-old';
    return false;
  },
);
// INT-11.8, INT-11.10: at start the background connects, says hello, and reads the state.
capable.then((ok) => ok && state());

/** Opens the port; `retry` marks the reconnect after a port closed (INT-11.8). */
function connect(retry = false) {
  const mine = { port: browser.runtime.connectNative(HOST), hello: null, answer: null };
  const since = Date.now();
  link = mine;
  mine.port.onMessage.addListener((message) => link === mine && take(mine, message));
  mine.port.onDisconnect.addListener(() => {
    void browser.runtime.lastError;
    if (link !== mine) return;
    link = null;
    reach = 'not-reachable';
    mine.answer?.reject(fail(reach));
    end(reach);
    // INT-11.8: connect again at once and say hello; when that port also closes
    // within a second, stop until the next need, so a missing host makes no loop.
    if (!retry || Date.now() - since >= QUICK) {
      connect(true);
      state();
    }
  });
}

/** One plain or boxed message from the port. */
function take(mine, message) {
  if (!message || typeof message !== 'object') return;
  if (message.type === 'box') {
    unbox(message);
  } else if (message.type === 'hello') {
    mine.answer?.resolve(message);
  } else if (message.type === 'error') {
    const n = message.error;
    if (n === 3 || n === 41) {
      again(); // they answer boxes only, never a hello
    } else if (mine.answer) {
      // The hello's own answer; 4 belongs to an older session's request.
      if (n !== 4) mine.answer.reject(fail((reach = n === 44 || n === 45 ? n : 'not-reachable')));
    } else if (n === 4) {
      end('not-reachable'); // INT-11.10: a new hello, no retry
      if (fours) return; // a second plain 4 in a row: not reachable, no hello until the next need (INT-11.8)
      fours = true;
      state().finally(() => {
        fours = false;
      });
    } else if (n === 44 || n === 45) {
      end((reach = n)); // the port stays open; the next need says hello (INT-11.8)
    }
  }
}

/** The session, saying hello first when there is none (INT-01.20). */
async function ready() {
  if (!(await capable)) throw fail('too-old');
  if (session) return session;
  if (!link) connect();
  const mine = link;
  mine.hello ??= hello(mine, true).finally(() => {
    mine.hello = null;
  });
  return mine.hello;
}

async function hello(mine, once) {
  const c = await channel.keyPair();
  const C = await channel.publicBytes(c.publicKey);
  if (link !== mine) throw fail(reach);
  let timer;
  const reply = await new Promise((resolve, reject) => {
    mine.answer = { resolve, reject };
    // A hello that gets no answer ends after INT-11.10's wait: Larsal is not reachable (LD-520 (1)).
    timer = setTimeout(() => reject(fail((reach = 'not-reachable'))), WAIT);
    mine.port.postMessage({ type: 'hello', versions: [1], key: encode(C), browser: BROWSER });
  }).finally(() => {
    clearTimeout(timer);
    mine.answer = null;
  });
  const A = decode(reply.key, 32);
  if (reply.version !== 1 || !A || typeof reply.sid !== 'string') throw fail((reach = 'not-reachable'));
  let keys;
  try {
    keys = await channel.sessionKeys(c.privateKey, C, A);
  } catch (e) {
    // INT-11.7: an all-zero X25519 result; drop this session and say hello once more.
    if (once && e?.name === 'OperationError') return hello(mine, false);
    throw fail((reach = 'not-reachable'));
  }
  if (link !== mine) throw fail(reach);
  const app = typeof reply.app === 'string' ? reply.app : '';
  session = { sid: reply.sid, ...keys, C, A, app, requests: new Requests(), proof: null, proven: false };
  reach = 'ok';
  quiet(browser.storage.local.set({ last_app_version: app }));
  return session;
}

/** Ends the session: every request in it fails with `why`. */
function end(why) {
  const jobs = session ? session.requests.drain() : [];
  session = null;
  for (const job of jobs) {
    clearTimeout(job.timer);
    job.reject(fail(why));
  }
}

/**
 * Plain error 3 or 41 (INT-11.10). It carries no `req`, so it names no request: the session ends,
 * a new hello and `check` with the proof follow, and then every request that was in flight and
 * does not wait for the user is sent once more on the new session. A request that waits for the
 * user (`connect`) is told that the session ended and is never sent again (no second Connect
 * dialog, INT-11.25). Requests whose box never went out, those queued past the 8 in flight among
 * them, go to the new session. A 3 or 41 while that `check` waits, or for a request already sent
 * again, is the second failure: Larsal is not reachable, and no hello follows until the next need.
 */
async function again() {
  if (redo) {
    if (session) end('not-reachable'); // it answers the new session's boxes, its `check` first
    return; // no new session yet: it answers another box of the ended one
  }
  if (!session) return;
  const jobs = session.requests.drain();
  session = null;
  for (const job of jobs) clearTimeout(job.timer);
  redo = true;
  const why = await request('check', {}, { prove: true }).then(() => null, (e) => e.reach ?? 'not-reachable');
  redo = false;
  for (const job of jobs) {
    const resend = Boolean(job.sent); // its box went out
    if (resend && job.waits) job.reject(fail('ended'));
    else if (why || (resend && job.retried)) job.reject(fail(why || 'not-reachable'));
    else submit(Object.assign(job, { retried: job.retried || resend, sent: 0 }));
  }
}

/** One request of INT-01.30; resolves with Larsal's reply object, `error` included. */
function request(type, fields = {}, how = {}) {
  return new Promise((resolve, reject) => {
    submit({ type, fields, prove: Boolean(how.prove), waits: Boolean(how.waits), resolve, reject, retried: false });
  });
}

async function submit(job) {
  let s;
  try {
    s = await ready();
  } catch (e) {
    job.reject(e);
    return;
  }
  const req = s.requests.add(job);
  if (req) send(s, req, job);
}

async function send(s, req, job) {
  try {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const content = { ...job.fields, type: job.type, req };
    if (job.prove) Object.assign(content, await proof(s, nonce));
    const box = await channel.seal(s.request, nonce, text.encode(JSON.stringify(content)));
    if (s !== session || s.requests.flying.get(req) !== job) return; // ended meanwhile; its caller was told
    job.nonce = nonce;
    job.sent = true; // its box went out (again)
    link.port.postMessage({ type: 'box', sid: s.sid, nonce: encode(nonce), box: encode(box) });
    if (!job.waits) job.timer = setTimeout(() => finish(s, req, fail('not-reachable')), WAIT);
  } catch {
    finish(s, req, fail('not-reachable'));
  }
}

/** Ends request `req` with its reply or an Error, and sends the next one waiting (INT-11.10). */
function finish(s, req, outcome) {
  const job = s.requests.flying.get(req);
  if (!job) return;
  clearTimeout(job.timer);
  const next = s.requests.done(req);
  if (next) send(s, ...next);
  if (outcome instanceof Error) return job.reject(outcome);
  if (job.prove && !Object.hasOwn(outcome, 'error')) s.proven = true; // Larsal took the proof (INT-01.28)
  job.resolve(outcome);
}

/** `id_key` and `proof` (INT-01.28): C sealed under the proof key with this request's nonce. */
async function proof(s, nonce) {
  const pair = await identification();
  const I = await channel.publicBytes(pair.publicKey);
  if (!s.proof || !same(s.proof.I, I)) s.proof = { I, key: channel.proofKey(pair.privateKey, s.C, s.A, I) };
  return { id_key: encode(I), proof: encode(await channel.seal(await s.proof.key, nonce, s.C)) };
}

/** A boxed message: a reply to a waiting request, a notice, or nothing (INT-11.10). */
async function unbox(message) {
  const s = session;
  const nonce = decode(message.nonce, 12);
  const box = decode(message.box, 16, true);
  if (!s || message.sid !== s.sid || !nonce || !box) return;
  let content;
  try {
    content = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await channel.open(s.reply, nonce, box)));
  } catch {
    return; // a box that does not open, or no JSON: dropped
  }
  const what = s.requests.match(content, nonce);
  if (what === 'notice') {
    tell(); // INT-11.10: nothing else is done
  } else if (what) {
    finish(s, what, content);
  }
}

/**
 * The state the popup and the options page show (INT-11.10, INT-11.23): one
 * fresh `check` (with the proof) and one `status`, after each hello and at
 * each ask. No reply is kept.
 */
async function state() {
  let got;
  try {
    const s = await ready();
    const check = await request('check', {}, { prove: true });
    const status = await request('status');
    got = { reach, app: s.app, check, status, connecting: pairing !== null, refused };
    // INT-11.25, INT-11.39: the first connection shows the words of the session its `connect` goes on.
    if (check.error === 8 && s === session) got.words = await words(s);
  } catch (e) {
    got = { reach: e.reach ?? 'not-reachable' };
  }
  // INT-11.8, INT-11.10: when a state read finds Larsal reachable where the last one did not, or the other way
  // round, the open pages read the state again (after a plain 4 too, whose new hello no page asked for).
  if (got.reach !== 'ended' && (got.reach === 'ok') !== reached) {
    reached = got.reach === 'ok';
    tell();
  }
  return got;
}

/** INT-11.39: the four pairing words of session `s` and the identification key, as Larsal shows them. */
async function words(s) {
  list ??= fetch(browser.runtime.getURL('words.txt'))
    .then((r) => r.text())
    .then((t) => t.split('\n').slice(0, -1));
  const I = await channel.publicBytes((await identification()).publicKey);
  const input = new Uint8Array([...text.encode(PAIRING), ...s.A, ...s.C, ...I]);
  return pairingWords(new Uint8Array(await crypto.subtle.digest('SHA-256', input)), await list);
}

/**
 * `connect` (INT-11.25): at most one waits for Larsal's dialog. Larsal's Deny (error 6) is kept until
 * the next `connect`, so the next popup shows MI11-61 with Try Again in place of a new dialog.
 */
function pair() {
  refused = false;
  pairing ??= request('connect', {}, { prove: true, waits: true })
    .then((reply) => {
      refused = reply.error === 6;
      return reply;
    })
    .finally(() => {
      pairing = null;
    });
  return pairing;
}

/**
 * The popup's Cancel on the first connection (INT-11.25, port route): the session ends first, so
 * every caller still waiting under it (the `connect` too) is told `ended` at once; then a new hello
 * on the same port replaces the session in Larsal, which closes its Connect dialog as Deny
 * (INT-01.20, LD-520 (5)).
 */
async function cancel() {
  if (session) end('ended');
  await ready();
  return {};
}

/**
 * `unlock` (INT-11.26, B8): no field at all; Larsal shows its own unlock panel, or answers error 1. At most one
 * waits, as for `connect`: a second Unlock while one waits sends nothing and gets the same reply.
 */
function unlock() {
  unlocking ??= request('unlock', {}, { waits: true }).finally(() => {
    unlocking = null;
  });
  return unlocking;
}

/**
 * `fields.found` from a content script: `logins.find` for its top frame with
 * the URLs of MessageSender only (INT-11.11: nothing of the body is used), and
 * the tab's badge (INT-11.42).
 */
async function fieldsFound(message, who) {
  if (who.frameId !== 0) return {};
  const s = await ready();
  if (!s.proven) await request('check', {}, { prove: true });
  if (!s.proven || s !== session) return {};
  const found = await request('logins.find', { url: who.url, top_url: who.topUrl });
  const n = Array.isArray(found.entries) ? found.entries.length : 0;
  await browser.action.setBadgeText({ tabId: who.tabId, text: n ? String(n) : '' });
  return {};
}

// INT-11.12: each internal route, the sender classes it takes and what the background does.
const ROUTES = new Map([
  ['popup.status', [['P'], state]],
  ['options.status', [['P'], state]],
  ['popup.connect', [['P'], pair]],
  ['popup.cancel', [['P'], cancel]],
  ['popup.unlock', [['P'], unlock]],
  ['fields.found', [['C'], fieldsFound]],
]);

browser.runtime.onMessage.addListener((message, sender, reply) => {
  const who = classify(sender, SELF);
  const row = who && typeof message?.route === 'string' ? ROUTES.get(message.route) : undefined;
  if (!row || !row[0].includes(who.kind)) return false; // refused: no reply, nothing done (INT-11.11)
  row[1](message, who).then(reply, (e) => reply({ error: e?.reach ?? 'not-reachable' }));
  return true;
});

/**
 * INT-11.8: while Larsal answers 44 or 45, a new hello every second as long as a
 * popup or the options page is open, so Larsal started later is reached without
 * a reload; once reached, the pages read the state again (state() tells them).
 */
function tick() {
  if (!pages.size) {
    clearInterval(pace);
    pace = null;
  } else if ((reach === 44 || reach === 45) && !session) {
    pacing ??= state().finally(() => {
      pacing = null;
    });
  }
}

// The popup and the options page each hold one runtime port named "page" while
// they are open (P senders only, INT-11.12); any other port is closed at once.
browser.runtime.onConnect.addListener((port) => {
  if (port.name !== 'page' || classify(port.sender, SELF)?.kind !== 'P') return port.disconnect();
  pages.add(port);
  port.onDisconnect.addListener(() => pages.delete(port));
  pace ??= setInterval(tick, QUICK);
});
