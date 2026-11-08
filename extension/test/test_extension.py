"""Tests of the extension core, Chrome build (story E7-S7c; INT-11, INT-01).

Run, after building Larsal's two test programs (`larsal-bridge`, and the test
Larsal of crates/larsal-browser/examples/test_larsal.rs):

    cargo build --offline --locked -p larsal-bridge
    cargo build --offline --locked -p larsal-browser --example test_larsal
    python3 -I extension/test/test_extension.py

The programs are read from $CARGO_TARGET_DIR/debug (default: target/debug). The
package checks need only Python and macOS's jsc. The browser checks run the
installed Chrome through driver.py (headless, a test HOME under /tmp, the mock
keychain, the window guard), Larsal's own browser side as the test Larsal over
one demo vault, and larsal-bridge as Chrome's native host with a test instance
folder. No window, no network beyond 127.0.0.1, nothing outside /tmp (AGENTS.md
rules 5, 7, 10, 11).
"""

import base64
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True  # no __pycache__ in the tree
HERE = os.path.dirname(os.path.abspath(__file__))
EXTENSION = os.path.dirname(HERE)
sys.path[:0] = [HERE, EXTENSION]
import build  # noqa: E402
import driver  # noqa: E402
import test_channel_vectors as vectors  # noqa: E402

TARGET = os.environ.get("CARGO_TARGET_DIR") or os.path.join(os.path.dirname(EXTENSION), "target")
BRIDGE = os.path.join(TARGET, "debug", "larsal-bridge")
LARSAL = os.path.join(TARGET, "debug", "examples", "test_larsal")
JSC = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/A/Helpers/jsc"

# INT-11.1 and its test T01: what no file of a package may hold.
BANNED = (
    r"innerHTML", r"outerHTML", r"insertAdjacentHTML", r"document\.write", r"\beval\(", r"new Function",
    r"\bfetch\((?!browser\.runtime\.getURL\()", r"XMLHttpRequest", r"WebSocket", r"EventSource", r"sendBeacon",
    r"onMessageExternal", r"onConnectExternal", r"\bset(?:Timeout|Interval)\(\s*['\"`]",
    r"\bconsole\.",  # INT-11.15: nothing the extension holds goes to a log or the console
)
# Test-only seams (INT-11.43): the browser tests write them into their own copy of a built package;
# build.py never does, and PackageChecks proves no built package holds one. name: (file, text, seam).
SEAM = "test seam"
SHORT_WAIT = 5  # seconds: INT-11.10's 60-second wait in the test package, so T21 runs in seconds
SEAMS = {
    "short-wait": ("background.js", "const WAIT = 60_000;", "const WAIT = %d_000; // %s" % (SHORT_WAIT, SEAM)),
    # T07: WebCrypto without X25519, so INT-11.5's start check fails.
    "no-x25519": ("background.js", "// INT-11.5: without X25519",
                  "crypto.subtle.generateKey = () => Promise.reject(new DOMException('%s', 'NotSupportedError'));\n"
                  "// INT-11.5: without X25519" % SEAM),
}
URL = re.compile(r"\b(?:https?|wss?|ftp)://[^\s'\"`<>)]*")

STATUS = "chrome.runtime.sendMessage({ route: 'options.status' })"
# The identification key's record, read from IndexedDB in the extension's origin (INT-11.6).
ID_KEY = """new Promise((resolve, reject) => {
  const asked = indexedDB.open('bridge');
  asked.onerror = () => reject(asked.error);
  asked.onsuccess = () => {
    const db = asked.result;
    const get = db.transaction('keys').objectStore('keys').get('identification');
    get.onerror = () => reject(get.error);
    get.onsuccess = async () => {
      const pair = get.result;
      db.close();
      if (!pair) return resolve(null);
      const tries = {};
      for (const form of ['raw', 'pkcs8', 'jwk', 'spki']) {
        tries[form] = await crypto.subtle.exportKey(form, pair.privateKey).then(() => 'exported', (e) => e.name);
      }
      const pub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
      resolve({
        stores: Array.from(db.objectStoreNames), algorithm: pair.privateKey.algorithm.name,
        extractable: pair.privateKey.extractable, usages: pair.privateKey.usages, tries,
        public: btoa(String.fromCharCode(...pub)),
        local: await chrome.storage.local.get(null),
      });
    };
  };
})"""
# INT-01.50 through the extension's own channel.js: the keys are WebCrypto's, the
# secrets are the test vectors' (RFC 7748's Alice as c, Bob as a, and i).
CHANNEL = """(async () => {
  const ch = await import('/channel.js');
  const s = crypto.subtle, X = { name: 'X25519' };
  const bytes = (h) => Uint8Array.from(h.match(/../g), (b) => parseInt(b, 16));
  const hex = (b) => Array.from(new Uint8Array(b), (x) => x.toString(16).padStart(2, '0')).join('');
  const secret = (h) => s.importKey('pkcs8', bytes('302e020100300506032b656e04220420' + h), X, false,
    ['deriveKey', 'deriveBits']);
  const nine = await s.importKey('raw', bytes('09' + '00'.repeat(31)), X, true, []);
  const pub = async (k) => new Uint8Array(await s.deriveBits({ name: 'X25519', public: nine }, k, 256));
  const [c, a, i] = await Promise.all(['%(c)s', '%(a)s', '%(i)s'].map(secret));
  const [C, A, I] = await Promise.all([c, a, i].map(pub));
  const n = (last) => Uint8Array.from({ length: 12 }, (_, k) => (k === 11 ? last : 0));
  const keys = await ch.sessionKeys(c, C, A);
  const proof = await ch.proofKey(i, C, A, I);
  const r = { C: hex(C), A: hex(A), CV6: hex(I) };
  r.CV4 = hex(await ch.seal(keys.request, n(1), new TextEncoder().encode('%(p1)s')));
  r.CV5_opened = new TextDecoder().decode(await ch.open(keys.reply, n(1), bytes('%(cv5)s')));
  r.CV9 = hex(await ch.seal(proof, n(2), C));
  r.keys = [keys.request, keys.reply, proof].map((k) => [k.algorithm.name, k.algorithm.length, k.extractable, k.usages]);
  r.request_opens = await ch.open(keys.request, n(1), bytes(r.CV4)).then(() => 'opened', (e) => e.name);
  r.reply_seals = await ch.seal(keys.reply, n(1), C).then(() => 'sealed', (e) => e.name);
  r.export = await s.exportKey('raw', keys.request).then(() => 'exported', (e) => e.name);
  const fresh = await ch.keyPair();
  r.fresh = [fresh.privateKey.extractable, fresh.privateKey.usages, (await ch.publicBytes(fresh.publicKey)).length];
  return r;
})()"""
# Runs a script in a tab as the extension's content script (scripting.executeScript, the
# ISOLATED world), sending one runtime message from each frame (the body names other URLs).
AS_CONTENT = """(async () => {
  const [tab] = await chrome.tabs.query({ url: '%(match)s' });
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    args: [%(message)s],
    func: (message) => chrome.runtime.sendMessage(message).then(
      (reply) => ({ frame: location.href, reply: reply === undefined ? 'none' : reply }),
      (e) => ({ frame: location.href, refused: String(e && e.message) })),
  });
  return { tab: tab.id, frames: results.map((r) => r.result),
           badge: await chrome.action.getBadgeText({ tabId: tab.id }) };
})()"""
# The same, each frame opening a "page" port: "closed" when the background closes it within 2 s.
AS_CONTENT_PORT = """(async () => {
  const [tab] = await chrome.tabs.query({ url: '%(match)s' });
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    func: () => new Promise((resolve) => {
      const port = chrome.runtime.connect({ name: 'page' });
      port.onDisconnect.addListener(() => resolve({ frame: location.href, port: 'closed' }));
      setTimeout(() => resolve({ frame: location.href, port: 'open' }), 2000);
    }),
  });
  return results.map((r) => r.result);
})()"""
# A host that answers each hello with an all-zero key (INT-11.7 step 3, T13), or with "version-2" a usable key
# (X25519's base point) and version 2 (INT-01.20); it logs each message's type and browser.
ZERO_HOST = """import base64, json, struct, sys
stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
while True:
    head = stdin.read(4)
    if len(head) < 4:
        break
    message = json.loads(stdin.read(struct.unpack("=I", head)[0]))
    with open(sys.argv[1], "a") as log:
        log.write("%s %s\\n" % (message.get("type"), message.get("browser")))
    answer = {"type": "error", "error": 44}
    if message.get("type") == "hello":
        answer = {"type": "hello", "version": 1, "sid": "zero", "app": "0.1.0",
                  "key": base64.b64encode(bytes(32)).decode()}
        if sys.argv[2:] == ["version-2"]:
            answer.update(version=2, key=base64.b64encode(bytes([9]) + bytes(31)).decode())
    data = json.dumps(answer).encode()
    stdout.write(struct.pack("=I", len(data)) + data)
    stdout.flush()
"""
# A host between Chrome and larsal-bridge (INT-11.10's plain errors, T20, T21). It relays every
# frame both ways and logs "<type> <step>" for each frame from Chrome. For each box it takes the next
# step of the plan file (a JSON list; "pass" when empty): "pass"; "drop" (never answered); "hold" (answered with
# plain 4 when Chrome's next hello comes, before that hello goes on: "hello after-4"); "other-sid" (Larsal's next
# box comes back under another sid); or a number, a plain error answered in Larsal's place (the box never
# reaches it).
PROXY = """import json, os, struct, subprocess, sys, threading
plan, log, pids, program = sys.argv[1:5]
child = subprocess.Popen([program] + sys.argv[5:], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
with open(pids, "a") as f:
    f.write("%d\\n" % child.pid)
lock, other_sid, held = threading.Lock(), [], []

def read(stream):
    head = stream.read(4)
    return stream.read(struct.unpack("=I", head)[0]) if len(head) == 4 else None

def write(stream, data):
    with lock:
        stream.write(struct.pack("=I", len(data)) + data)
        stream.flush()

def step():
    try:
        with open(plan) as f:
            steps = json.load(f)
    except FileNotFoundError:
        steps = []
    if not steps:
        return "pass"
    with open(plan + ".next", "w") as f:
        json.dump(steps[1:], f)
    os.replace(plan + ".next", plan)
    return steps[0]

def replies():
    while True:
        data = read(child.stdout)
        if data is None:
            break
        message = json.loads(data)
        if message.get("type") == "box" and other_sid:
            other_sid.pop()
            message["sid"] = "x" + message["sid"]
            data = json.dumps(message).encode()
        write(sys.stdout.buffer, data)

threading.Thread(target=replies, daemon=True).start()
while True:
    data = read(sys.stdin.buffer)
    if data is None:
        break
    kind = json.loads(data).get("type")
    what = step() if kind == "box" else "pass"
    if kind == "hello" and held:
        held.pop()
        what = "after-4"
        write(sys.stdout.buffer, json.dumps({"type": "error", "error": 4}).encode())
    with open(log, "a") as f:
        f.write("%s %s\\n" % (kind, what))
    if what == "hold":
        held.append(1)
    if what in ("drop", "hold"):
        continue
    if isinstance(what, int):
        write(sys.stdout.buffer, json.dumps({"type": "error", "error": what}).encode())
        continue
    if what == "other-sid":
        other_sid.append(1)
    write(child.stdin, data)
child.stdin.close()
child.wait()
"""
# Makes the background's X25519 key agreement fail with an error that is not OperationError (DevTools,
# in the service worker); `delete crypto.subtle.deriveKey` undoes it.
BREAK_X25519 = """(() => {
  const real = SubtleCrypto.prototype.deriveKey;
  crypto.subtle.deriveKey = function (algorithm, ...rest) {
    return algorithm && algorithm.name === 'X25519'
      ? Promise.reject(new DOMException('test', 'NotSupportedError')) : real.call(this, algorithm, ...rest);
  };
  return 1;
})()"""
# INT-11.6 in the extension's origin with its own idkey.js: another call stores its key between this
# call's read (no record) and its write; then the record is put back as it was.
FIRST_KEY_WINS = """(async () => {
  const { identification } = await import('/idkey.js');
  const idb = (mode, act) => new Promise((resolve, reject) => {
    const asked = indexedDB.open('bridge');
    asked.onerror = () => reject(asked.error);
    asked.onsuccess = () => {
      const db = asked.result, t = db.transaction('keys', mode), r = act(t.objectStore('keys'));
      t.oncomplete = () => { db.close(); resolve(r.result); };
      t.onabort = () => { db.close(); reject(t.error); };
    };
  });
  const raw = async (pair) => btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))));
  const kept = await idb('readonly', (s) => s.get('identification'));
  const real = SubtleCrypto.prototype.generateKey;
  const first = await real.call(crypto.subtle, { name: 'X25519' }, false, ['deriveKey']);
  let made = null, returned = null;
  await idb('readwrite', (s) => s.delete('identification'));
  crypto.subtle.generateKey = async function (...args) {
    made = await real.apply(this, args);
    await idb('readwrite', (s) => s.put(first, 'identification'));
    return made;
  };
  try { returned = await identification(); } finally { delete crypto.subtle.generateKey; }
  const out = { first: await raw(first), made: made && await raw(made), returned: await raw(returned),
                stored: await raw(await idb('readonly', (s) => s.get('identification'))) };
  await idb('readwrite', (s) => s.put(kept, 'identification'));
  out.restored = await raw(await idb('readonly', (s) => s.get('identification'))) === await raw(kept);
  return out;
})()"""
# An options page in an iframe of the options page sends options.status: "none" when refused (INT-11.12).
OPTIONS_IN_A_FRAME = """new Promise((resolve) => {
  const frame = document.createElement('iframe');
  frame.onload = () => frame.contentWindow.chrome.runtime.sendMessage({ route: 'options.status' }).then(
    (reply) => resolve(reply === undefined ? 'none' : reply), () => resolve('none')).finally(() => frame.remove());
  frame.src = 'options.html';
  document.body.append(frame);
})"""

RUN = {}


def setUpModule():
    RUN["start"] = time.time()


def tearDownModule():
    # LD-276, LD-278 (3): after the run, macOS's own log shows no keychain write by a PID of the run.
    driver.check_keychain_log(RUN["start"])


def banned(name, text, allowed=()):
    """T01's findings in one file: each banned name, and each URL that is not one of `allowed`."""
    found = ["%s: %s" % (name, p) for p in BANNED if re.search(p, text)]
    return found + ["%s: %s" % (name, u) for u in URL.findall(text) if u not in allowed]


def package(folder, dev=False):
    return build.build("chrome", os.path.join(folder, "chrome"), dev)


def test_package(folder, *seams):
    """The development package with the test options page (it stands in for E7-S7f's) and `seams`."""
    pkg = package(folder, dev=True)
    os.makedirs(os.path.join(pkg, "options"))
    shutil.copyfile(os.path.join(HERE, "page", "options.html"), os.path.join(pkg, "options", "options.html"))
    for name in seams:
        file, old, new = SEAMS[name]
        with open(os.path.join(pkg, file)) as f:
            text = f.read()
        if text.count(old) != 1:
            raise AssertionError("seam %s: %r is not in %s once" % (name, old, file))
        with open(os.path.join(pkg, file), "w") as f:
            f.write(text.replace(old, new))
    return pkg


def write_script(home, name, body):
    path = driver.inside(home, name)
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o700)
    return path


def setup_host(home, program):
    """Larsal's own setup code writes Chrome's host file into the test HOME (INT-01.8 to INT-01.10)."""
    out = subprocess.run([LARSAL, "setup", home, program, build.DEV_ID], check=True, capture_output=True,
                         text=True, env={"HOME": home, "PATH": "/usr/bin:/bin"}).stdout.strip()
    if out != os.path.join(home, driver.NATIVE_HOSTS, "app.larsal.browser.json"):
        raise AssertionError("setup wrote %r" % out)


class PackageChecks(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="larsal-ext-build-", dir="/tmp")
        self.addCleanup(shutil.rmtree, self.folder, True)

    def read(self, out):
        with open(os.path.join(out, "manifest.json")) as f:
            return json.load(f)

    def test_built_manifest_has_the_default_csp_and_only_b2s_permissions(self):
        m = self.read(package(self.folder))
        self.assertEqual(m["content_security_policy"], {"extension_pages": "script-src 'self'; object-src 'self'"})
        self.assertEqual(m["permissions"], ["nativeMessaging", "storage", "activeTab", "scripting"])
        self.assertEqual(m["host_permissions"], ["http://*/*", "https://*/*"])
        for absent in ("optional_permissions", "optional_host_permissions", "externally_connectable", "key",
                       "content_scripts", "sandbox", "update_url"):
            self.assertNotIn(absent, m)
        self.assertEqual((m["manifest_version"], m["name"], m["default_locale"]), (3, "Larsal", "en"))
        self.assertEqual(m["version"], build.larsal_version())
        self.assertEqual(m["minimum_chrome_version"], "133")
        self.assertEqual(m["background"], {"service_worker": "background.js", "type": "module",
                                           "scripts": ["background.js"]})
        self.assertEqual(m["action"], {"default_popup": "popup/popup.html"})
        self.assertEqual(m["options_ui"], {"page": "options/options.html", "open_in_tab": True})
        self.assertEqual(m["web_accessible_resources"][0]["use_dynamic_url"], True)
        self.assertEqual({k: v["suggested_key"]["default"] for k, v in m["commands"].items()},
                         {"_execute_action": "Alt+Shift+A", "fill-best-match": "Alt+Shift+F",
                          "generate-password": "Alt+Shift+G"})

    def test_key_only_in_development_builds_and_its_id_is_the_debug_id(self):
        dev = self.read(package(os.path.join(self.folder, "dev"), dev=True))
        self.assertEqual(dev["key"], build.DEV_KEY)
        self.assertEqual(build.extension_id(dev["key"]), build.DEV_ID)
        self.assertRegex(build.DEV_ID, r"^[a-p]{32}$")
        self.assertNotIn("key", self.read(package(os.path.join(self.folder, "store"))))

    def test_a_package_holds_only_the_files_it_uses(self):
        out = package(self.folder)
        files = sorted(os.path.relpath(os.path.join(d, f), out) for d, _, fs in os.walk(out) for f in fs)
        used, todo = set(), ["background.js"]  # the service worker and every module it imports
        while todo:
            name = todo.pop()
            used.add(name)
            with open(os.path.join(EXTENSION, name)) as f:
                todo += [m for m in re.findall(r"^import .* from '\./([\w.]+)';$", f.read(), re.M) if m not in used]
        self.assertEqual(files, sorted(used | {"manifest.json", "_locales/en/messages.json"}))
        for name in build.FILES:
            with open(os.path.join(out, name), "rb") as a, open(os.path.join(EXTENSION, name), "rb") as b:
                self.assertEqual(a.read(), b.read(), name)  # copied as written: no bundler, no minifier
        with self.assertRaises(FileExistsError):
            package(self.folder)  # a build never writes over another one

    def test_no_file_of_a_package_holds_inner_html_eval_or_a_remote_url(self):
        out = package(self.folder, dev=True)
        hosts = tuple(self.read(out)["host_permissions"])
        found = []
        for d, _, fs in os.walk(out):
            for f in fs:
                with open(os.path.join(d, f), encoding="utf-8") as text:
                    found += banned(os.path.relpath(os.path.join(d, f), out), text.read(),
                                    hosts if f == "manifest.json" else ())
        self.assertEqual(found, [])
        self.assertTrue(all("package.json" not in f and ".min." not in f for f in build.FILES))

    def test_the_search_finds_each_banned_use(self):
        # T01's search itself: each pattern is seen, so a clean result above means something.
        for text in ("el.innerHTML = x", "el.outerHTML", "el.insertAdjacentHTML('a', b)", "document.write(x)",
                     "eval(x)", "new Function('x')", "fetch('/x')", "fetch(url)", "new XMLHttpRequest()",
                     "new WebSocket(u)", "new EventSource(u)", "navigator.sendBeacon(u)",
                     "browser.runtime.onMessageExternal", "browser.runtime.onConnectExternal",
                     "setTimeout('x()', 1)", "setInterval(`x`, 1)", "a = 'https://example.test/x'",
                     "// see http://example.test", "x = 'wss://example.test'", "console.log(reply)",
                     "globalThis.console.error(e)"):
            self.assertNotEqual(banned("f", text), [], text)
        self.assertEqual(banned("f", "fetch(browser.runtime.getURL('words.txt'))"), [])
        self.assertEqual(banned("f", "setTimeout(() => x(), 1); evaluate(y); retrieval(z)"), [])
        self.assertEqual(banned("m", '"http://*/*", "https://*/*"', ("http://*/*", "https://*/*")), [])

    def test_no_built_package_holds_a_test_seam(self):
        # The browser tests' seams go only into their own copies (test_package); each one's text is in the
        # source once, and neither a store nor a development package holds any seam.
        for dev in (False, True):
            out = package(os.path.join(self.folder, "dev" if dev else "store"), dev)
            for d, _, fs in os.walk(out):
                for f in fs:
                    with open(os.path.join(d, f), encoding="utf-8") as text:
                        self.assertNotIn(SEAM, text.read(), f)
        for name, (file, old, new) in SEAMS.items():
            with open(os.path.join(EXTENSION, file)) as f:
                self.assertEqual(f.read().count(old), 1, name)
            self.assertIn(SEAM, new, name)
        self.assertIn("const WAIT = 60_000;", SEAMS["short-wait"][1])  # the card's 60 s, in every built package

    def test_the_suite_run_ends_with_the_keychain_check(self):
        # LD-276, LD-278 (3): tearDownModule calls driver.check_keychain_log for the whole run.
        calls = []
        with mock.patch.object(driver, "check_keychain_log", calls.append):
            tearDownModule()
        self.assertEqual(calls, [RUN["start"]])

    def test_the_loopback_check_reports_any_other_address(self):
        lsof = "p4242\nf5\nn127.0.0.1:50000->127.0.0.1:8443\nf6\nn[::1]:50001->[::1]:8443\nf7\nn*:5353\n" \
               "f8\nn192.168.1.20:50002->142.250.1.1:443\nf9\nn127.0.0.1:50003->10.0.0.1:53\n"
        with mock.patch.object(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, lsof)):
            self.assertEqual(outside_loopback([4242]),
                             ["192.168.1.20:50002->142.250.1.1:443", "127.0.0.1:50003->10.0.0.1:53"])

    def test_pure_modules_pass_under_macos_jsc(self):
        run = subprocess.run([JSC, "-m", os.path.join(HERE, "pure_test.js")], capture_output=True, text=True,
                             cwd=HERE, env={"PATH": "/usr/bin:/bin"}, timeout=60)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn("pure: all passed", run.stdout)
        self.assertNotIn("FAIL", run.stdout)


class Larsal:
    """The test Larsal (test_larsal run): its output lines, and its standard input for the dialog."""

    def __init__(self, folder, site, home):
        self.lines, self.cv = [], threading.Condition()
        self.process = subprocess.Popen([LARSAL, "run", folder, site], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, text=True, cwd=folder,
                                        env={"HOME": home, "TMPDIR": folder, "PATH": "/usr/bin:/bin"})
        driver.RUN_PIDS.add(self.process.pid)
        threading.Thread(target=self._read, daemon=True).start()
        self.wait(r"^ready$")

    def _read(self):
        for line in self.process.stdout:
            with self.cv:
                self.lines.append(line.rstrip("\n"))
                self.cv.notify_all()
        with self.cv:
            self.lines.append("(ended)")
            self.cv.notify_all()

    def mark(self):
        with self.cv:
            return len(self.lines)

    def since(self, mark):
        with self.cv:
            return list(self.lines[mark:])

    def wait(self, pattern, mark=0, timeout=15):
        def find():
            return next((m for m in map(re.compile(pattern).search, self.lines[mark:]) if m), None)
        with self.cv:
            self.cv.wait_for(lambda: find() is not None, timeout)
            found = find()
        if not found:
            raise AssertionError("test Larsal never said /%s/; it said: %s" % (pattern, self.since(mark)))
        return found

    def say(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()

    def stop(self):
        """Ends it by closing its input; by its own PID if it does not end."""
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                os.kill(self.process.pid, signal.SIGKILL)
                self.process.wait(10)
        self.process.stdout.close()


def pid_log(path):
    try:
        with open(path) as f:
            return [int(p) for p in f.read().split()]
    except FileNotFoundError:
        return []


def wait_for(check, timeout=10, step=0.1):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()


def outside_loopback(pids):
    """Internet sockets of `pids` whose address is not loopback (lsof, read only)."""
    rows = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-i", "-p", ",".join(map(str, pids)), "-F", "n"],
                          capture_output=True, text=True).stdout.splitlines()
    names = [r[1:] for r in rows if r.startswith("n")]
    local = re.compile(r"^(?:127\.0\.0\.1|\[::1\]|\*|localhost):[0-9*]+$")
    return [n for n in names if not all(local.match(part) for part in n.split("->"))]


class ChromeWithLarsal(unittest.TestCase):
    """One headless Chrome with the development package, in steps that build on each other."""

    @classmethod
    def setUpClass(cls):
        for program in (BRIDGE, LARSAL):
            if not os.access(program, os.X_OK):
                raise AssertionError("missing %s: build it first (see the module's text)" % program)
        cls.folder = tempfile.mkdtemp(prefix="larsal-ext-", dir="/tmp")
        cls.home = driver.check_test_home(os.path.join(cls.folder, "home"))  # a new folder under /tmp
        cls.instance = os.path.join(cls.folder, "i")
        os.makedirs(cls.home)
        os.makedirs(cls.instance, 0o700)
        cls.pkg = test_package(cls.folder, "short-wait")
        cls.bridge_pids = os.path.join(cls.folder, "bridge-pids")
        cls.quick_pids = os.path.join(cls.folder, "quick-pids")
        cls.zero_pids = os.path.join(cls.folder, "zero-pids")
        cls.proxy_pids = os.path.join(cls.folder, "proxy-pids")  # PROXY, and the larsal-bridge each one starts
        cls.proxied_pids = os.path.join(cls.folder, "proxied-pids")
        cls.plan_file = os.path.join(cls.folder, "proxy-plan")
        cls.proxy_log_file = os.path.join(cls.folder, "proxy-log")
        cls.relay = cls.script("relay.sh", 'echo $$ >> "%s"\nLARSAL_TEST_INSTANCE_DIR="%s" exec "%s" "$@"\n'
                               % (cls.bridge_pids, cls.instance, BRIDGE))
        cls.quick = cls.script("quick.sh", 'echo $$ >> "%s"\nexit 0\n' % cls.quick_pids)
        cls.larsal = None
        cls.sites = driver.TestSites(cls.folder)
        cls.site = cls.sites.url("site-a.test", "/")
        cls.chrome = None
        try:
            cls.chrome = driver.Chrome(sites=cls.sites, home=cls.home)
            cls.setup_host(cls.quick)  # first a host that exits at once (INT-11.8's no-loop rule)
            cls.id = cls.chrome.load_extension(cls.pkg)
            cls.page = cls.chrome.open("chrome-extension://%s/options/options.html" % cls.id)
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def script(cls, name, body):
        return write_script(cls.home, name, body)

    @classmethod
    def setup_host(cls, program):
        setup_host(cls.home, program)

    @classmethod
    def host_pids(cls):
        return (pid_log(cls.bridge_pids) + pid_log(cls.zero_pids) + pid_log(cls.proxy_pids)
                + pid_log(cls.proxied_pids))

    @classmethod
    def tearDownClass(cls):
        problems = []
        if cls.larsal:
            cls.larsal.stop()
        for pid in cls.host_pids() + pid_log(cls.quick_pids):
            driver.RUN_PIDS.add(pid)  # for the after-run keychain check (LD-276)
        if cls.chrome:
            try:
                cls.chrome.close()  # fails on a guard hit, a focus change or a changed owner file
            except driver.DriverError as e:
                problems.append(str(e))
        cls.sites.close()
        shutil.rmtree(cls.folder, ignore_errors=True)
        if problems:
            raise AssertionError("; ".join(problems))

    def tearDown(self):
        # Chrome reaches nothing beyond loopback (the driver's resolver rules); checked after each step.
        outside = outside_loopback(self.chrome.pids() + self.host_pids())
        if outside:
            self.chrome._kill()  # Chrome's PID, the one the driver started
            self.fail("STOP: a process of the run reached beyond loopback: %s" % outside)

    def start_larsal(self, enabled=True):
        with open(os.path.join(self.instance, "settings.json"), "w") as f:
            json.dump({"browser.enabled": enabled}, f)  # S-BRW-01 in the test settings file
        type(self).larsal = Larsal(self.instance, self.site, self.home)
        return self.larsal

    def stop_larsal(self):
        self.larsal.stop()
        type(self).larsal = None

    def status(self):
        return self.page.eval(STATUS)

    def test_01_a_missing_host_is_tried_at_start_and_once_per_need_with_no_loop(self):
        # INT-11.8: at start, connect and hello; the port closes, one reconnect closes within 1 s: stop.
        self.assertEqual(self.id, build.DEV_ID)  # the id Larsal's host file allows (INT-01.9)
        wait_for(lambda: len(pid_log(self.quick_pids)) >= 2, 10)
        time.sleep(2.5)
        self.assertEqual(len(pid_log(self.quick_pids)), 2)
        self.assertEqual(self.status(), {"reach": "not-reachable"})
        time.sleep(2.5)
        self.assertEqual(len(pid_log(self.quick_pids)), 4)  # the need's port, and its one reconnect

    def test_02_with_larsal_not_running_the_background_reports_it_as_not_reachable(self):
        self.setup_host(self.relay)  # now larsal-bridge, through the relay script (S-BRW-24)
        self.assertEqual(self.status(), {"reach": 44})  # INT-01.5: Larsal is not running
        self.assertEqual(len(pid_log(self.bridge_pids)), 1)
        self.assertEqual(self.status(), {"reach": 44})
        self.assertEqual(len(pid_log(self.bridge_pids)), 1)  # 44 keeps the port open (INT-11.8)

    def test_03_larsal_started_later_is_reached_without_a_reload(self):
        # INT-11.8, T14: the open page holds its "page" port; while Larsal answers 44 or 45 the
        # background says hello every second on its own, and tells the page once Larsal is reached.
        self.page.eval("window.seen = []; chrome.runtime.onMessage.addListener((m) => { seen.push(m); });"
                       " window.pagePort = chrome.runtime.connect({ name: 'page' }); 1")
        self.start_larsal(enabled=False)
        self.assertEqual(self.status(), {"reach": 45})  # Larsal runs, browser integration off
        self.stop_larsal()
        larsal = self.start_larsal()
        larsal.wait(r"^request check ", timeout=2)  # within 2 s of Larsal listening, no page asking (T14)
        larsal.wait(r"^request status ", timeout=2)
        self.assertEqual(wait_for(lambda: self.page.eval("window.seen"), 3), [{"notice": "state"}])
        self.page.eval("window.pagePort.disconnect(); 1")
        got = self.status()
        self.assertEqual(got["reach"], "ok")
        self.assertEqual(got["app"], "0.1.0")
        self.assertEqual(got["check"]["error"], 8)  # this browser is not connected yet (INT-01.28)
        self.assertEqual(got["status"]["vaults"], [{"name": "demo-vault", "shown": True, "state": "unlocked"}])
        self.assertEqual(len(pid_log(self.bridge_pids)), 1)  # the same port: no reload, no new host
        larsal.wait(r"^request check url= top_url= identity=\S{44}$")
        larsal.wait(r"^reply check error 8$")
        larsal.wait(r"^request status ")

    def test_04_connect_is_answered_in_larsals_dialog_and_then_check_passes(self):
        larsal = self.larsal
        mark = larsal.mark()
        self.page.eval("window.pairing = chrome.runtime.sendMessage({ route: 'popup.connect' }); 1")
        question = larsal.wait(r"^question (\d+) connect (.+)$", mark)
        self.assertEqual(self.status()["connecting"], True)  # one connect in flight
        larsal.say("allow %s Chrome on Test Mac" % question.group(1))  # the test seam answers the dialog
        reply = self.page.eval("window.pairing", timeout=30)
        self.assertEqual((reply["type"], reply["name"]), ("connect", "Chrome on Test Mac"))
        self.assertRegex(reply["vault"], r"^[A-Za-z0-9_-]{22}$")
        got = self.status()
        self.assertEqual(got["check"]["vaults"], [{"id": reply["vault"], "name": "demo-vault",
                                                   "connection": "Chrome on Test Mac"}])
        self.assertEqual(got["status"]["vaults"][0]["connection"], "Chrome on Test Mac")
        self.assertEqual(got["connecting"], False)
        larsal.wait(r"^reply connect ok$", mark)
        larsal.wait(r"^reply check ok$", mark)

    def test_05_the_identification_key_lives_in_indexeddb_and_cannot_be_exported(self):
        key = self.page.eval(ID_KEY)
        self.assertEqual((key["stores"], key["algorithm"], key["extractable"], key["usages"]),
                         (["keys"], "X25519", False, ["deriveKey"]))
        self.assertEqual(key["tries"], {"raw": "InvalidAccessError", "pkcs8": "InvalidAccessError",
                                        "jwk": "InvalidAccessError", "spki": "InvalidAccessError"})
        self.assertEqual(len(base64.b64decode(key["public"])), 32)
        self.assertEqual(key["local"], {"last_app_version": "0.1.0"})  # no key in storage.local (INT-11.6)
        seen = {m.group(1) for m in map(re.compile(r"^request \S+ .*identity=(\S+)$").search, self.larsal.lines) if m}
        self.assertEqual(seen, {key["public"]})  # the key Larsal saw proven is this one

    def test_06_a_content_script_message_naming_another_url_or_origin_changes_nothing(self):
        tab = self.chrome.open(self.site)
        self.addCleanup(tab.close)
        site_b = self.sites.url("site-b.test", "/")
        mark = self.larsal.mark()
        body = json.dumps({"route": "fields.found", "url": site_b, "top_url": site_b, "origin": site_b[:-1],
                           "tab": {"id": 1, "url": site_b}, "frameId": 0})
        got = self.page.eval(AS_CONTENT % {"match": "https://site-a.test/*", "message": body})
        frames = {f["frame"]: f["reply"] for f in got["frames"]}
        # INT-11.12: fields.found answers nothing secret: an empty object to the top frame and to the subframe.
        self.assertEqual(frames, {self.site: {}, self.sites.url("site-b.test", "/frame.html"): {}})
        self.larsal.wait(r"^reply logins.find ok$", mark)
        lines = self.larsal.since(mark)
        finds = [line for line in lines if line.startswith("request ")]
        self.assertEqual(len(finds), 1, lines)  # the top frame's only; the site-b frame asked nothing
        self.assertRegex(finds[0], r"^request logins\.find url=%s top_url=%s identity=" % ((re.escape(self.site),) * 2))
        self.assertNotIn("site-b", "\n".join(lines))
        self.assertEqual(got["badge"], "1")  # INT-11.42: one match for the top frame
        badge = "chrome.action.getBadgeText({ tabId: %d })" % got["tab"]
        tab.navigate(self.site)  # a new document in the tab: Chrome clears the tab's own badge (INT-11.42)
        self.assertEqual(wait_for(lambda: self.page.eval(badge) == "", 5), True)
        # The options page in a subframe is not the options page (P only at frameId 0, INT-11.12).
        mark = self.larsal.mark()
        self.assertEqual(self.page.eval(OPTIONS_IN_A_FRAME), "none")
        time.sleep(1)
        self.assertEqual(self.larsal.since(mark), [])
        # Routes of the popup and the options page are refused from a content script: no reply, nothing done.
        for route in ("popup.connect", "popup.status", "options.status", "no.such.route"):
            mark = self.larsal.mark()
            body = json.dumps({"route": route, "url": self.page_url(), "origin": "chrome-extension://" + self.id})
            got = self.page.eval(AS_CONTENT % {"match": "https://site-a.test/*", "message": body})
            for frame in got["frames"]:
                self.assertEqual(frame.get("reply", "none"), "none", frame)  # refused, or no reply at all
            time.sleep(1)
            self.assertEqual(self.larsal.since(mark), [], route)
        # A content script's "page" port is closed at once: only the popup and the options page pace hellos.
        got = self.page.eval(AS_CONTENT_PORT % {"match": "https://site-a.test/*"})
        self.assertEqual({f["frame"]: f["port"] for f in got},
                         {self.site: "closed", self.sites.url("site-b.test", "/frame.html"): "closed"})

    def page_url(self):
        return "chrome-extension://%s/options/options.html" % self.id

    def test_07_the_channel_gives_the_same_bytes_in_webcrypto_and_larsal_crypto(self):
        rust = json.loads(subprocess.run([LARSAL, "vectors"], check=True, capture_output=True, text=True,
                                         env={"PATH": "/usr/bin:/bin"}).stdout)
        script = CHANNEL % {"c": vectors.C_SECRET, "a": vectors.A_SECRET, "i": vectors.I_SECRET,
                            "p1": vectors.P1, "cv5": rust["CV5"]}
        web = self.page.eval(script)
        for name in ("C", "A", "CV4", "CV6", "CV9"):
            self.assertEqual(web[name], rust[name], name)
        for name in ("CV4", "CV5", "CV6", "CV9"):
            self.assertEqual(rust[name], vectors.EXPECTED[name], name)  # and INT-01.50's table
        self.assertEqual(web["CV5_opened"], vectors.P2)  # Larsal's reply opens with the reply key
        self.assertEqual(web["keys"], [["AES-GCM", 256, False, ["encrypt"]], ["AES-GCM", 256, False, ["decrypt"]],
                                       ["AES-GCM", 256, False, ["encrypt"]]])
        self.assertEqual((web["request_opens"], web["reply_seals"], web["export"]),
                         ("InvalidAccessError", "InvalidAccessError", "InvalidAccessError"))
        self.assertEqual(web["fresh"], [False, ["deriveKey"], 32])

    def test_08_a_notice_makes_the_pages_read_the_state_again(self):
        self.page.eval("window.notices = []; chrome.runtime.onMessage.addListener((m) => { notices.push(m); }); 1")
        self.larsal.say("lock")
        self.larsal.wait(r"^locked$")
        notices = wait_for(lambda: self.page.eval("window.notices"), 10)
        self.assertEqual(notices, [{"notice": "state"}])
        got = self.status()
        self.assertEqual(got["status"]["vaults"][0]["state"], "locked")
        self.assertIn(got["check"]["error"], (1, 8))
        self.larsal.say("unlock")
        self.assertEqual(wait_for(lambda: len(self.page.eval("window.notices")) == 2, 10), True)
        self.assertNotIn("error", self.status()["check"])

    def test_09_when_larsal_bridge_stops_the_background_connects_again_and_says_hello(self):
        before = pid_log(self.bridge_pids)
        mark = self.larsal.mark()
        os.kill(before[-1], signal.SIGTERM)  # the host Chrome started for this run (in RUN_PIDS at the end)
        self.assertEqual(len(wait_for(lambda: len(pid_log(self.bridge_pids)) > len(before) and
                                      pid_log(self.bridge_pids), 10)), len(before) + 1)
        # A new hello on the new port, with no page asking (INT-11.8), and the state read after it
        # (INT-11.10). Exactly one check: a request under the old sid would get plain 3 and a second one.
        self.larsal.wait(r"^reply status ok$", mark)
        self.assertEqual([line.split()[1] for line in self.larsal.since(mark) if line.startswith("request ")],
                         ["check", "status"])
        self.assertEqual(self.status()["reach"], "ok")
        self.assertEqual(len(pid_log(self.bridge_pids)), len(before) + 1)

    def test_10_larsal_quitting_mid_session_is_reported_then_reached_again(self):
        self.stop_larsal()
        self.assertEqual(self.status(), {"reach": 44})  # the session's next box gets the relay's 44
        larsal = self.start_larsal()
        time.sleep(2.5)  # no page holds its "page" port now: no hello of the background's own (INT-11.8)
        self.assertEqual([line for line in larsal.lines if line.startswith("request ")], [])
        got = self.status()
        self.assertEqual(got["reach"], "ok")
        self.assertEqual(got["check"]["error"], 8)  # a new Larsal holds no connection (its vault is new)

    def test_11_a_larsal_restart_between_two_requests_gets_one_hello_check_and_resend(self):
        self.stop_larsal()
        larsal = self.start_larsal()  # the background still holds the old session: its sid is unknown now
        got = self.status()
        self.assertEqual(got["reach"], "ok")  # INT-11.10: plain 3, then hello, check, and the request once more
        self.assertEqual(got["check"]["error"], 8)
        requests = [line.split()[1] for line in larsal.lines if line.startswith("request ")]
        self.assertEqual(requests, ["check", "check", "status"])  # the retry's check, the resent one, status
        # Two requests in flight when Larsal restarts: two plain 3s, one hello, one check, each resent once.
        self.stop_larsal()
        larsal = self.start_larsal()
        both = self.page.eval("Promise.all([%s, %s])" % (STATUS, STATUS))
        self.assertEqual([(g["reach"], g["check"]["error"]) for g in both], [("ok", 8), ("ok", 8)])
        requests = sorted(line.split()[1] for line in larsal.lines if line.startswith("request "))
        self.assertEqual(requests, ["check", "check", "check", "status", "status"])

    def test_12_an_all_zero_x25519_result_gets_one_more_hello_then_not_reachable(self):
        # INT-11.7 step 3, T13: WebCrypto's OperationError; the background says hello once more, then
        # reports Larsal as not reachable, and sends no box under such a session.
        log = os.path.join(self.folder, "zero-log")
        program = driver.inside(self.home, "zero.py")
        with open(program, "w") as f:
            f.write(ZERO_HOST)
        self.setup_host(self.script("zero.sh", 'echo $$ >> "%s"\nexec "%s" -B -I "%s" "%s"\n'
                                    % (self.zero_pids, sys.executable, program, log)))
        os.kill(pid_log(self.bridge_pids)[-1], signal.SIGTERM)  # the port closes; the reconnect reaches the zero host
        def read():
            with open(log) as f:
                return f.read()
        self.assertTrue(wait_for(lambda: os.path.exists(log) and read() == "hello Chrome\n" * 2, 10), "the reconnect's hellos")
        time.sleep(1.5)
        self.assertEqual(read(), "hello Chrome\n" * 2)  # one more hello, then nothing until the next need
        self.assertEqual(self.status(), {"reach": "not-reachable"})
        self.assertEqual(read(), "hello Chrome\n" * 4)  # the need's hello and its one more; never a box
        self.assertEqual(len(pid_log(self.zero_pids)), 1)  # the port stays open

    def test_12a_a_hello_reply_of_another_version_makes_no_session(self):
        # INT-01.20: the background speaks version 1 only; a hello reply with version 2 (and a usable key) is
        # not taken: Larsal is not reachable, and no box is sent.
        log = os.path.join(self.folder, "version-log")
        self.setup_host(self.script("version.sh", 'echo $$ >> "%s"\nexec "%s" -B -I "%s" "%s" version-2\n'
                                    % (self.zero_pids, sys.executable, driver.inside(self.home, "zero.py"), log)))
        os.kill(pid_log(self.zero_pids)[-1], signal.SIGTERM)  # the reconnect reaches the version-2 host
        def read():
            with open(log) as f:
                return f.read()
        self.assertTrue(wait_for(lambda: os.path.exists(log) and read(), 10), "the reconnect's hello")
        time.sleep(1.5)
        self.assertEqual(self.status(), {"reach": "not-reachable"})
        self.assertEqual(read(), "hello Chrome\n" * 2)  # the reconnect's hello and the need's; never a box

    # From test_13 on Chrome's host is PROXY: larsal-bridge behind a relay that can answer a box in
    # Larsal's place (plain errors), drop it, or send Larsal's reply back under another sid.
    def plan(self, *steps):
        with open(self.plan_file + ".new", "w") as f:
            json.dump(list(steps), f)
        os.replace(self.plan_file + ".new", self.plan_file)

    def proxy_log(self):
        try:
            with open(self.proxy_log_file) as f:
                return f.read().splitlines()
        except FileNotFoundError:
            return []

    def requests_since(self, mark):
        return [line.split()[1] for line in self.larsal.since(mark) if line.startswith("request ")]

    def test_13_plain_error_4_ends_the_session_and_a_new_hello_follows_with_no_retry(self):
        program = driver.inside(self.home, "proxy.py")
        with open(program, "w") as f:
            f.write(PROXY)
        self.setup_host(self.script("proxy.sh", 'echo $$ >> "%s"\nLARSAL_TEST_INSTANCE_DIR="%s" exec "%s" -B -I %s "$@"\n'
                                    % (self.proxy_pids, self.instance, sys.executable, " ".join(
                                        '"%s"' % p for p in (program, self.plan_file, self.proxy_log_file,
                                                             self.proxied_pids, BRIDGE)))))
        mark = self.larsal.mark()
        os.kill(pid_log(self.zero_pids)[-1], signal.SIGTERM)  # the port closes; the reconnect reaches the relay
        self.larsal.wait(r"^reply status ok$", mark)
        self.assertEqual(self.proxy_log(), ["hello pass", "box pass", "box pass"])  # hello, check, status
        # INT-11.10: plain 4 (the box did not open): the session ends, a new hello, nothing is sent again.
        self.plan(4)
        mark, seen = self.larsal.mark(), len(self.proxy_log())
        self.assertEqual(self.status(), {"reach": "not-reachable"})  # its check got 4: the caller is told
        self.larsal.wait(r"^reply status ok$", mark)  # the new session's state read
        time.sleep(1.5)
        self.assertEqual(self.proxy_log()[seen:], ["box 4", "hello pass", "box pass", "box pass"])
        self.assertEqual(self.requests_since(mark), ["check", "status"])  # the check that got 4 never again
        self.assertEqual(self.status()["reach"], "ok")

    def test_14_a_plain_41_while_a_connect_waits_resends_the_status_and_never_the_connect(self):
        # INT-11.10: the requests in flight that do not wait for the user are sent again; the waiting connect's
        # callers are told the session ended, so Larsal never shows a second Connect dialog (INT-11.25). Two
        # popup.connect: one connect.
        mark = self.larsal.mark()
        self.page.eval("window.pairs = [1, 2].map(() => chrome.runtime.sendMessage({ route: 'popup.connect' })); 1")
        self.larsal.wait(r"^question \d+ connect ", mark)
        time.sleep(SHORT_WAIT + 1)  # T21: past the (test package's) wait, a connect still waits for the user
        self.assertEqual(self.status()["connecting"], True)
        self.plan("pass", 41)  # the state read's check goes through; its status gets plain 41
        resent = self.larsal.mark()
        got = self.status()
        self.assertEqual((got["reach"], got["status"]["vaults"][0]["name"]), ("ok", "demo-vault"))
        self.assertEqual(self.page.eval("Promise.all(window.pairs)"), [{"error": "ended"}, {"error": "ended"}])
        time.sleep(1.5)
        self.assertEqual(self.requests_since(resent), ["check", "check", "status"])  # the new hello's check, then status
        lines = self.larsal.since(mark)
        self.assertEqual([line.split()[0] for line in lines if line.startswith(("question ", "request connect "))],
                         ["request", "question"], lines)

    def test_15_a_second_plain_41_reports_larsal_as_not_reachable(self):
        # T20: one new hello, one check, one resent status; when that one gets 41 too, Larsal is not reachable.
        self.plan("pass", 41, "pass", 41)
        mark, seen = self.larsal.mark(), len(self.proxy_log())
        self.assertEqual(self.status(), {"reach": "not-reachable"})  # told after the second hello's check
        time.sleep(1)
        self.assertEqual(self.proxy_log()[seen:], ["box pass", "box 41", "hello pass", "box pass", "box 41",
                                                   "hello pass", "box pass"])
        self.assertEqual(self.requests_since(mark), ["check", "check", "check"])  # never the status

    def test_15a_a_plain_41_for_the_new_hellos_check_is_the_second_failure(self):
        # INT-11.10, INT-11.8 (no loop): the relay answers every box with 41. One new hello and its check; that
        # check's 41 is the second failure: not reachable at once, and no further hello until the next need,
        # with a page open (the pace runs only while Larsal answers 44 or 45).
        self.plan(*[41] * 12)
        self.page.eval("window.pagePort = chrome.runtime.connect({ name: 'page' }); 1")
        try:
            seen, start = len(self.proxy_log()), time.monotonic()
            self.assertEqual(self.status(), {"reach": "not-reachable"})
            self.assertLess(time.monotonic() - start, SHORT_WAIT)  # told at the 41, not after the wait
            time.sleep(2.5)
            self.assertEqual(self.proxy_log()[seen:], ["box 41", "hello pass", "box 41"])
        finally:
            self.page.eval("window.pagePort.disconnect(); 1")
        self.plan()
        self.assertEqual(self.status()["reach"], "ok")  # the next need says hello
        self.assertEqual(self.proxy_log()[seen + 3:], ["hello pass", "box pass", "box pass"])

    def test_15b_after_a_plain_41_every_request_in_flight_that_does_not_wait_is_sent_again(self):
        # INT-11.10: a plain 41 names no request. Ten state reads at once: eight checks in flight (the relay
        # answers seven never and the eighth with 41) and two queued past the 8 (INT-01.44). After the new
        # hello's check the eight are sent once more and the two queued go to the new session: each caller is
        # answered, none by its wait.
        self.plan(*["drop"] * 7, 41)
        mark, seen, start = self.larsal.mark(), len(self.proxy_log()), time.monotonic()
        got = self.page.eval("Promise.all(Array.from({ length: 10 }, () => %s))" % STATUS, timeout=SHORT_WAIT + 15)
        self.assertEqual([g["reach"] for g in got], ["ok"] * 10)
        self.assertLess(time.monotonic() - start, SHORT_WAIT)
        self.assertEqual(self.proxy_log()[seen:seen + 9], ["box drop"] * 7 + ["box 41", "hello pass"])
        self.assertEqual(sorted(self.requests_since(mark)), ["check"] * 11 + ["status"] * 10)

    def test_15c_a_plain_4_during_a_hello_does_not_fail_it(self):
        # INT-11.10: a plain 4 answers a box, never a hello. The relay holds one check's box and answers the
        # other with 4: the session ends, each caller is told, the background says hello; the held box's 4
        # comes while that hello waits, and the hello still makes the new session.
        self.plan("hold", 4)
        mark, seen = self.larsal.mark(), len(self.proxy_log())
        self.assertEqual(self.page.eval("Promise.all([%s, %s])" % (STATUS, STATUS)), [{"reach": "not-reachable"}] * 2)
        self.larsal.wait(r"^reply status ok$", mark)  # the new session's state read
        time.sleep(1)
        self.assertEqual(self.proxy_log()[seen:], ["box hold", "box 4", "hello after-4", "box pass", "box pass"])
        self.assertEqual(self.requests_since(mark), ["check", "status"])
        self.assertEqual(self.status()["reach"], "ok")

    def test_16_a_request_with_no_reply_fails_as_not_reachable_after_the_wait(self):
        # INT-11.10, T21: a request that does not wait for the user fails as not reachable after 60 seconds
        # (SHORT_WAIT in the test package); the session lives on.
        self.plan("drop")
        start = time.monotonic()
        self.assertEqual(self.page.eval(STATUS, timeout=SHORT_WAIT + 15), {"reach": "not-reachable"})
        self.assertGreaterEqual(time.monotonic() - start, SHORT_WAIT - 0.5)
        self.assertEqual(self.status()["reach"], "ok")

    def test_17_a_reply_under_another_sid_is_dropped(self):
        # INT-01.21, INT-11.10: a box whose sid is not the session's is dropped; its request then times out.
        self.plan("other-sid")
        mark = self.larsal.mark()
        self.assertEqual(self.page.eval(STATUS, timeout=SHORT_WAIT + 15), {"reach": "not-reachable"})
        self.assertEqual(self.requests_since(mark), ["check"])  # Larsal answered it; the background dropped it
        self.assertEqual(self.status()["reach"], "ok")

    def test_18_only_an_all_zero_x25519_result_gets_one_more_hello(self):
        # INT-11.7 step 3: one more hello only after OperationError; any other failure of the key agreement
        # reports Larsal as not reachable at once. The background's WebCrypto is broken through DevTools.
        worker = self.chrome.worker(self.id)
        worker.eval(BREAK_X25519)
        try:
            seen = len(self.proxy_log())
            os.kill(pid_log(self.proxy_pids)[-1], signal.SIGTERM)  # the reconnect says hello
            self.assertTrue(wait_for(lambda: self.proxy_log()[seen:], 10))
            time.sleep(1.5)
            self.assertEqual(self.proxy_log()[seen:], ["hello pass"])
        finally:
            worker.eval("delete crypto.subtle.deriveKey; 1")
        self.assertEqual(self.status()["reach"], "ok")

    def test_19_no_hello_pace_while_the_host_is_missing(self):
        # INT-11.8: the 1-second pace runs only while Larsal answers 44 or 45; never for a host that closes.
        self.setup_host(self.quick)
        self.page.eval("window.pagePort = chrome.runtime.connect({ name: 'page' }); 1")
        try:
            before = len(pid_log(self.quick_pids))
            os.kill(pid_log(self.proxy_pids)[-1], signal.SIGTERM)
            self.assertTrue(wait_for(lambda: len(pid_log(self.quick_pids)) > before, 10))
            time.sleep(3.5)
            self.assertEqual(len(pid_log(self.quick_pids)), before + 1)  # the reconnect only
        finally:
            self.page.eval("window.pagePort.disconnect(); 1")

    def test_20_the_first_identification_key_stored_wins(self):
        # INT-11.6: the key is written with IndexedDB `add`, so a key another call stored first is never replaced.
        got = self.page.eval(FIRST_KEY_WINS)
        self.assertNotEqual(got["made"], got["first"])
        self.assertEqual((got["returned"], got["stored"], got["restored"]), (got["first"], got["first"], True))


class ChromeWithoutX25519(unittest.TestCase):
    """T07, INT-11.5: a browser whose WebCrypto lacks X25519 (the test package's seam) opens no port."""

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp(prefix="larsal-ext-", dir="/tmp")
        cls.addClassCleanup(shutil.rmtree, cls.folder, True)
        cls.home = driver.check_test_home(os.path.join(cls.folder, "home"))
        os.makedirs(cls.home)
        cls.pids = os.path.join(cls.folder, "host-pids")
        pkg = test_package(cls.folder, "no-x25519")
        cls.chrome = driver.Chrome(home=cls.home)  # it makes the profile, where Larsal writes the host file
        cls.addClassCleanup(cls.chrome.close)  # fails on a guard hit, a focus change or a changed owner file
        setup_host(cls.home, write_script(cls.home, "host.sh", 'echo $$ >> "%s"\nexit 0\n' % cls.pids))
        cls.id = cls.chrome.load_extension(pkg)
        cls.page = cls.chrome.open("chrome-extension://%s/options/options.html" % cls.id)

    @classmethod
    def tearDownClass(cls):
        driver.RUN_PIDS.update(pid_log(cls.pids))  # none when the rule holds; for the keychain check (LD-276)

    def tearDown(self):
        self.assertEqual(outside_loopback(self.chrome.pids()), [])

    def test_a_browser_without_x25519_opens_no_port_and_reports_too_old(self):
        self.assertEqual(self.id, build.DEV_ID)  # the id the host file allows
        time.sleep(1.5)  # the start check has run
        self.assertEqual(self.page.eval(STATUS), {"reach": "too-old"})  # E7-S7d shows MI11-60
        self.assertEqual(pid_log(self.pids), [])  # no port was opened: the host never started


if __name__ == "__main__":
    unittest.main(verbosity=2)
