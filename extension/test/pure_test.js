// The extension's pure modules under macOS's own JavaScript shell (INT-11.43;
// story E7-S7c): wire.js (strict base64, the request table) and routes.js (the
// sender classes). No browser and no outside package. Run:
//
//     /System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc -m extension/test/pure_test.js
//
// It prints one line per test and ends with "pure: N passed" (exit 0), or throws
// at the end naming each failed test (exit 3).

import { MAX_IN_FLIGHT, Requests, decode, encode, same } from '../wire.js';
import { classify, webOrigin } from '../routes.js';

const failed = [];
function test(name, body) {
  try {
    body();
    print(`ok ${name}`);
  } catch (e) {
    failed.push(name);
    print(`FAIL ${name}: ${e}`);
  }
}
function eq(got, want) {
  const g = JSON.stringify(got);
  const w = JSON.stringify(want);
  if (g !== w) throw new Error(`got ${g}, want ${w}`);
}
const bytes = (text) => Uint8Array.from(text, (c) => c.charCodeAt(0));
const list = (b) => (b ? Array.from(b) : b);

// RFC 4648 section 10.
const RFC = [
  ['', ''],
  ['f', 'Zg=='],
  ['fo', 'Zm8='],
  ['foo', 'Zm9v'],
  ['foob', 'Zm9vYg=='],
  ['fooba', 'Zm9vYmE='],
  ['foobar', 'Zm9vYmFy'],
];

test('base64 encodes the RFC 4648 vectors', () => {
  for (const [plain, coded] of RFC) eq(encode(bytes(plain)), coded);
  eq(encode(Uint8Array.from([0xfb, 0xff, 0xbf])), '+/+/');
});

test('base64 decodes the RFC 4648 vectors at their exact size', () => {
  for (const [plain, coded] of RFC) eq(list(decode(coded, plain.length)), list(bytes(plain)));
  eq(list(decode('+/+/', 3)), [0xfb, 0xff, 0xbf]);
});

test('base64 takes a size and "at least" only as asked', () => {
  eq(decode('Zm9v', 2), null);
  eq(decode('Zm9v', 4), null);
  eq(list(decode('Zm9vYmFy', 4, true)), list(bytes('foobar')));
  eq(decode('Zm9v', 4, true), null);
});

test('base64 refuses what INT-01.26 refuses', () => {
  for (const bad of [
    'Zm9', // no padding
    'Zg', // padding left out
    'Zg=', // short padding
    'Zh==', // trailing bits set
    'Zm9=', // trailing bits set
    'Zm-v', // base64url alphabet
    'Zm_v',
    'Zm9 ', // white space
    'Zm\n9v',
    '=Zm9',
    'Z=m9',
    'Zm9v====',
  ]) {
    eq([bad, decode(bad, 3)], [bad, null]);
    eq([bad, decode(bad, 1, true)], [bad, null]);
  }
  eq(decode(undefined, 0), null);
  eq(decode(42, 0), null);
});

test('same compares bytes', () => {
  eq(same(bytes('ab'), bytes('ab')), true);
  eq(same(bytes('ab'), bytes('ac')), false);
  eq(same(bytes('ab'), bytes('abc')), false);
});

const nonce = (n) => Uint8Array.from({ length: 12 }, (_, i) => (i === 11 ? n : 0));

test('requests count 1, 2, ... and at most 8 fly; later ones wait in order', () => {
  eq(MAX_IN_FLIGHT, 8);
  const t = new Requests();
  const jobs = Array.from({ length: 11 }, (_, i) => ({ type: 'status', n: i }));
  eq(jobs.map((j) => t.add(j)), [1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0]);
  eq(t.flying.size, 8);
  const [req, job] = t.done(3);
  eq([req, job.n], [9, 8]);
  eq(t.flying.size, 8);
  eq(t.done(999), null); // a req not in flight frees no place
  eq([t.flying.size, t.queue.length], [8, 2]);
  eq(t.done(9)[0], 10);
  eq([...t.flying.keys()], [1, 2, 4, 5, 6, 7, 8, 10]);
});

test('a request table never exceeds its limit', () => {
  const t = new Requests(2);
  eq([t.add({}), t.add({}), t.add({}), t.add({})], [1, 2, 0, 0]);
  eq(t.done(1)[0], 3);
  eq(t.flying.size, 2);
  eq(t.done(2)[0], 4);
  eq(t.done(3), null);
  eq(t.done(4), null);
  eq(t.flying.size, 0);
});

test('drain gives every job, flying then queued, and empties the table', () => {
  const t = new Requests(1);
  t.add({ n: 1 });
  t.add({ n: 2 });
  eq(t.drain().map((j) => j.n), [1, 2]);
  eq([t.flying.size, t.queue.length], [0, 0]);
  eq(t.add({ n: 3 }), 2); // req keeps counting in the session
});

test('a reply matches only its own req, type and nonce', () => {
  const t = new Requests();
  const job = { type: 'status' };
  const req = t.add(job);
  job.nonce = nonce(1);
  eq(t.match({ type: 'status', req }, nonce(1)), req);
  eq(t.match({ type: 'status', req }, nonce(2)), null);
  eq(t.match({ type: 'check', req }, nonce(1)), null);
  eq(t.match({ type: 'status', req: req + 1 }, nonce(1)), null);
  eq(t.match({ type: 'status', req: String(req) }, nonce(1)), null);
  const waiting = { type: 'status' }; // added, not yet sent: no nonce
  const r2 = t.add(waiting);
  eq(t.match({ type: 'status', req: r2 }, nonce(0)), null);
});

test('a box without req is a notice only when it says so', () => {
  const t = new Requests();
  eq(t.match({ type: 'notice', event: 'locked' }, nonce(5)), 'notice');
  eq(t.match({ type: 'status' }, nonce(5)), null);
  eq(t.match([], nonce(5)), null);
  eq(t.match(null, nonce(5)), null);
  eq(t.match('notice', nonce(5)), null);
  eq(t.match({ type: 'notice', req: 1 }, nonce(5)), null);
});

const SELF = { id: 'abcdefghijklmnopabcdefghijklmnop', origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop' };
const page = (path) => `${SELF.origin}${path}`;
const kind = (sender) => classify(sender, SELF)?.kind ?? null;

test('webOrigin reads only http and https origins, without user info', () => {
  eq(webOrigin('https://site-a.test/login'), 'https://site-a.test');
  eq(webOrigin('http://site-a.test:8080/'), 'http://site-a.test:8080');
  eq(webOrigin('https://user:pass@site-a.test/'), 'https://site-a.test');
  eq(webOrigin('https://site-b.test@site-a.test/'), 'https://site-a.test');
  eq(webOrigin('https://[::1]:8443/x'), 'https://[::1]:8443');
  eq(webOrigin('file:///tmp/x'), null);
  eq(webOrigin('data:text/html,x'), null);
  eq(webOrigin('javascript:alert(1)'), null);
  eq(webOrigin(`${SELF.origin}/popup/popup.html`), null);
  eq(webOrigin('https://site-a.test'), null); // not the serialized form
});

test('a content script is a web page in a tab, with its own origin', () => {
  const tab = { id: 7, url: 'https://site-a.test/' };
  const sender = { id: SELF.id, url: 'https://site-a.test/login', origin: 'https://site-a.test', tab, frameId: 0 };
  const who = classify(sender, SELF);
  eq([who.kind, who.url, who.topUrl, who.tabId, who.frameId], ['C', 'https://site-a.test/login', 'https://site-a.test/', 7, 0]);
  eq(kind({ ...sender, frameId: 4, url: 'https://sub.site-a.test/', origin: 'https://sub.site-a.test' }), 'C');
  eq(kind({ ...sender, url: 'https://u:p@site-a.test/x' }), 'C');
});

test('a sender that is not ours, or whose origin is not its URL, is refused', () => {
  const tab = { id: 7, url: 'https://site-a.test/' };
  const sender = { id: SELF.id, url: 'https://site-a.test/login', origin: 'https://site-a.test', tab, frameId: 0 };
  eq(kind({ ...sender, id: 'ponmlkjihgfedcbaponmlkjihgfedcba' }), null);
  eq(kind({ ...sender, id: undefined }), null);
  eq(kind({ ...sender, origin: 'null' }), null);
  eq(kind({ ...sender, origin: undefined }), null);
  eq(kind({ ...sender, origin: 'https://site-b.test' }), null);
  eq(kind({ ...sender, url: 'https://site-b.test@site-a.test/', origin: 'https://site-b.test' }), null);
  eq(kind({ ...sender, tab: undefined }), null);
  eq(kind({ ...sender, url: 'file:///tmp/a.html', origin: 'file://' }), null);
  eq(kind({ ...sender, url: undefined }), null);
  eq(kind(undefined), null);
});

test('the popup is exactly popup/popup.html with no tab', () => {
  const popup = { id: SELF.id, url: page('/popup/popup.html'), origin: SELF.origin };
  eq(kind(popup), 'P');
  eq(kind({ ...popup, tab: { id: 3 }, frameId: 0 }), null);
  eq(kind({ ...popup, url: page('/popup/popup.html?x') }), null);
  eq(kind({ ...popup, url: page('/popup/other.html') }), null);
  eq(kind({ ...popup, origin: 'chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba' }), null);
  eq(kind({ ...popup, url: `chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba/popup/popup.html` }), null);
});

test('the options page is exactly options/options.html as a top frame (frameId 0)', () => {
  const options = { id: SELF.id, url: page('/options/options.html'), origin: SELF.origin, tab: { id: 3 }, frameId: 0 };
  eq(kind(options), 'P');
  eq(kind({ ...options, tab: undefined }), 'P'); // sender.tab allowed, not needed (INT-11.12)
  eq(kind({ ...options, tab: undefined, frameId: undefined }), null);
  eq(kind({ ...options, tab: undefined, frameId: 2 }), null);
  eq(kind({ ...options, frameId: 2 }), null);
  eq(kind({ ...options, url: page('/options/options.html#x') }), null);
});

test('an in-page frame is ours under frames/, in a subframe of a tab', () => {
  const frame = { id: SELF.id, url: page('/frames/menu.html'), origin: SELF.origin, tab: { id: 3 }, frameId: 5 };
  eq(kind(frame), 'F');
  eq(kind({ ...frame, frameId: 0 }), null);
  eq(kind({ ...frame, tab: undefined }), null);
  eq(kind({ ...frame, frameId: undefined }), null);
  eq(kind({ ...frame, url: page('/frame/menu.html') }), null);
  eq(kind({ ...frame, url: page('/background.js') }), null);
});

if (failed.length) throw new Error(`pure: ${failed.length} failed: ${failed.join('; ')}`);
print(`pure: all passed`);
