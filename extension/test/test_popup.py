"""Tests of the popup's first frames, Chrome build (story E7-S7d; INT-11.23 to INT-11.26, INT-11.22).

Run as test_extension.py says (the same two test programs), then:

    python3 -I extension/test/test_popup.py

PopupWithLarsal opens the real popup (`action.openPopup` from the service worker, through DevTools) in the
installed Chrome, headless, through driver.py, over the test Larsal and larsal-bridge, and reads which frame
it draws. PopupParity draws the three frames from fed demo states (the test package's "fed-state" seam) and
compares each, light and dark, with the same frame of design/option-a/mockup.html rendered in the same
Chrome: every part's colours and font (BUILD-AND-VERIFY.md item 3), its box within 2 pt (item 4), pixel by
pixel (item 5: YIQ threshold 0.1, over 3 % fails), and the controls' names and tab order (item 7). The images and the
table go to $LARSAL_PARITY_DIR when set, else to the run's temporary folder. No window, no network beyond
127.0.0.1, nothing outside /tmp but that folder (AGENTS.md rules 5, 7, 10, 11).
"""

import base64
import json
import os
import shutil
import signal
import sys
import tempfile
import time
import unittest

sys.dont_write_bytecode = True  # no __pycache__ in the tree
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]
import build  # noqa: E402
import driver  # noqa: E402
import test_extension as ext  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(HERE))
MOCKUP = os.path.join(ROOT, "design", "option-a")
POPUP = "popup/popup.html"
# The test package's popup takes its state from window.fed when set, and window.redraw() reads it again.
ext.SEAMS["fed-state"] = ("popup/popup.js", "async function read() {\n",
                          "globalThis.redraw = () => refresh(); // %s\nasync function read() {\n"
                          "  if (globalThis.fed) return { ...globalThis.fed }; // %s\n" % (ext.SEAM, ext.SEAM))
# Every [data-msg] text, every [data-label] name and the title against chrome.i18n (INT-11.22).
FROM_MESSAGES = """(() => {
  const wrong = [];
  for (const el of document.querySelectorAll('[data-msg]')) {
    const want = chrome.i18n.getMessage(el.dataset.msg);
    if (!want || el.textContent !== want) wrong.push([el.dataset.msg, el.textContent]);
  }
  for (const el of document.querySelectorAll('[data-label]')) {
    const want = chrome.i18n.getMessage(el.dataset.label);
    if (!want || el.getAttribute('aria-label') !== want) wrong.push([el.dataset.label, el.getAttribute('aria-label')]);
  }
  if (document.title !== chrome.i18n.getMessage('MI11_101_a')) wrong.push(['title', document.title]);
  return wrong;
})()"""
# The visible texts of the shown frame, in order (hidden parts left out).
SHOWN_TEXT = """(() => {
  const frame = document.querySelector('[data-frame]:not([hidden])');
  const out = [];
  const walk = (el) => {
    if (el.hidden) return;
    for (const n of el.childNodes) {
      if (n.nodeType === 3 && n.data.trim()) out.push(n.data.trim());
      else if (n.nodeType === 1) walk(n);
    }
  };
  if (frame) walk(frame);
  return out;
})()"""
# Records the plaintext of every box the background seals (DevTools, in the service worker).
RECORD_BOXES = """(() => {
  globalThis.sealed = [];
  const real = SubtleCrypto.prototype.encrypt;
  crypto.subtle.encrypt = function (algorithm, key, data) {
    try { sealed.push(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data))); } catch {}
    return real.call(this, algorithm, key, data);
  };
  return 1;
})()"""
# Pixelmatch's colour delta (YIQ, threshold 0.1) over two PNGs; also a diff image (changed pixels red).
COMPARE = """(async () => {
  const load = (src) => new Promise((resolve, reject) => {
    const img = new Image();
    img.onload = () => resolve(img);
    img.onerror = reject;
    img.src = src;
  });
  const [a, b] = await Promise.all([load(%(a)s), load(%(b)s)]);
  const w = Math.max(a.width, b.width), h = Math.max(a.height, b.height);
  const pixels = (img) => {
    const c = new OffscreenCanvas(w, h), g = c.getContext('2d');
    g.fillStyle = '#ff00ff';
    g.fillRect(0, 0, w, h);
    g.drawImage(img, 0, 0);
    return g.getImageData(0, 0, w, h).data;
  };
  const p = pixels(a), q = pixels(b);
  const out = new OffscreenCanvas(w, h), g = out.getContext('2d'), d = g.createImageData(w, h);
  const y = (r, g, b) => r * 0.29889531 + g * 0.58662247 + b * 0.11448223;
  const i_ = (r, g, b) => r * 0.59597799 - g * 0.2741761 - b * 0.32180189;
  const q_ = (r, g, b) => r * 0.21147017 - g * 0.52261711 + b * 0.31114694;
  const max = 35215 * 0.1 * 0.1;
  let changed = 0;
  for (let k = 0; k < p.length; k += 4) {
    const [r1, g1, b1] = [p[k], p[k + 1], p[k + 2]], [r2, g2, b2] = [q[k], q[k + 1], q[k + 2]];
    const dy = y(r1, g1, b1) - y(r2, g2, b2), di = i_(r1, g1, b1) - i_(r2, g2, b2), dq = q_(r1, g1, b1) - q_(r2, g2, b2);
    const delta = 0.5053 * dy * dy + 0.299 * di * di + 0.1957 * dq * dq;
    const grey = 255 + (y(r1, g1, b1) - 255) * 0.1;
    if (delta > max) {
      changed++;
      d.data.set([255, 0, 0, 255], k);
    } else {
      d.data.set([grey, grey, grey, 255], k);
    }
  }
  g.putImageData(d, 0, 0);
  const blob = await out.convertToBlob({ type: 'image/png' });
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let bin = '';
  for (let k = 0; k < bytes.length; k += 32768) bin += String.fromCharCode(...bytes.subarray(k, k + 32768));
  return { a: [a.width, a.height], b: [b.width, b.height], changed, total: w * h, diff: btoa(bin) };
})()"""
# BUILD-AND-VERIFY.md items 3 and 4: every part the frame draws, with its colours and its box relative to the
# panel. Each text run (its own box, so wrappers do not matter) with its colour and font; each button (.btn)
# with its fill, corners and each edge; each icon by its glyph, with its colour and font; each other painted box
# (a fill or a visible edge: tiles, the checks' box and its rules, the word chips) in order, with its fill,
# corners, shadow and each edge. Texts and buttons are keyed by their words, so the two pages match word for word.
SPEC = """((root, panel, origin) => {
  const o = origin.getBoundingClientRect();
  const box = (r) => [r.x - o.x, r.y - o.y, r.width, r.height].map((v) => Math.round(v * 10) / 10);
  const clear = (c) => c === 'transparent' || /^rgba\\(.*,\\s*0\\)$/.test(c);
  const font = (s) => s.fontFamily.split(',')[0].replace(/['"]/g, '').trim();
  const edges = (s) => ['Top', 'Right', 'Bottom', 'Left'].map((side) => parseFloat(s['border' + side + 'Width'])
    ? s['border' + side + 'Width'] + ' ' + s['border' + side + 'Style'] + ' ' + s['border' + side + 'Color'] : '');
  const out = { panel: { style: [getComputedStyle(panel).backgroundColor] } }, seen = {};
  const put = (key, rect, style) => {
    seen[key] = (seen[key] || 0) + 1;
    out[seen[key] > 1 ? key + ' #' + seen[key] : key] = { box: box(rect), style };
  };
  for (const e of root.querySelectorAll('*')) {
    if (!e.getClientRects().length) continue;
    const s = getComputedStyle(e);
    for (const n of e.childNodes) {
      if (n.nodeType !== 3 || !n.data.trim()) continue;
      const r = document.createRange();
      r.setStart(n, n.data.search(/\\S/));
      r.setEnd(n, n.data.trimEnd().length);
      put('text ' + n.data.trim(), r.getBoundingClientRect(), [s.color, font(s), s.fontSize, s.fontWeight]);
    }
    const glyph = getComputedStyle(e, '::before').content;
    const painted = !clear(s.backgroundColor) || edges(s).some((x, i) => x && !clear(x.split(' ').slice(2).join(' ')));
    if (e.classList.contains('btn')) {
      put('btn ' + e.textContent.trim(), e.getBoundingClientRect(), [s.backgroundColor, s.borderRadius, ...edges(s)]);
    } else if (glyph && glyph !== 'none' && glyph !== 'normal') {
      put('icon ' + glyph, e.getBoundingClientRect(), [s.color, font(s), s.fontSize]);
    } else if (painted) {
      put('box', e.getBoundingClientRect(), [s.backgroundColor, s.borderRadius, s.boxShadow, ...edges(s)]);
    }
  }
  return out;
})(%s)"""
GEOMETRY = 2  # BUILD-AND-VERIFY.md item 4: within 2 pt in position and size (1 px = 1 pt at scale 1)
# BUILD-AND-VERIFY.md item 7: the frame's controls in tab order (no positive tabindex: document order), each with
# its accessible name and the message it comes from, and where it is.
CONTROLS = """(() => {
  const root = document.querySelector('[data-frame]:not([hidden])');
  return [...root.querySelectorAll('*')].filter((e) => e.getClientRects().length && e.tabIndex >= 0 && !e.disabled)
    .map((e) => {
      const id = e.dataset.msg || e.querySelector('[data-msg]')?.dataset.msg || null;
      const r = e.getBoundingClientRect();
      return { name: e.getAttribute('aria-label') || e.textContent.trim(), message: id && chrome.i18n.getMessage(id),
               tabindex: e.tabIndex, at: [Math.round(r.top), Math.round(r.left)] };
    });
})()"""
# Records what the popup asks for after this point, and stubs each way out, so nothing opens (D-INT11-1).
WATCH = """(() => {
  window.asked = [];
  const watch = (owner, name, label) => {
    const stub = (...args) => { asked.push([label, ...args]); return Promise.resolve({}); };
    owner[name] = stub;
    return owner[name] === stub;
  };
  return [watch(chrome.tabs, 'create', 'tabs.create'), watch(chrome.tabs, 'update', 'tabs.update'),
          watch(chrome.windows, 'create', 'windows.create'), watch(chrome.runtime, 'sendMessage', 'sendMessage'),
          watch(chrome.runtime, 'connect', 'connect'), watch(window, 'open', 'window.open')].every(Boolean) ? 1 : 0;
})()"""
# Demo states for the three locked frames (design/option-a/mockup.js, EXT.offline, EXT.pairing, EXT.locked).
VAULT = {"name": "Personal", "state": "unlocked", "shown": True}
FED = {
    "extension-popup-app-not-reachable": ("Popup · Larsal not reachable", {"reach": 44, "last": "1.0"}),
    "extension-popup-first-connection": ("Popup · first connection", {
        "reach": "ok", "status": {"vaults": [VAULT]}, "check": {"error": 8},
        "words": ["harbor", "quill", "ember", "forty-two"], "connecting": True}),
    "extension-popup-vault-locked": ("Popup · vault locked", {
        "reach": "ok", "check": {"error": 8}, "status": {"vaults": [
            dict(VAULT, state="locked"), {"name": "Work", "state": "locked"}, {"name": "Family", "state": "unlocked"}]}}),
}
# In the open popup: the frames it draws from now on, the notices it gets, and a mark that a reload would lose.
WATCH_FRAMES = """(() => {
  window.marker = 'same document';
  window.shownLog = [];
  window.notices = 0;
  new MutationObserver(() => shownLog.push(document.body.dataset.shown))
    .observe(document.body, { attributes: true, attributeFilter: ['data-shown'] });
  chrome.runtime.onMessage.addListener((m) => { if (m && m.notice === 'state') notices++; });
  return 1;
})()"""
# From the service worker: a content script in the site's tab sends the popup a state notice (another sender).
NOTICE_FROM_A_PAGE = """(async () => {
  const [tab] = await chrome.tabs.query({ url: 'https://site-a.test/*' });
  const [got] = await chrome.scripting.executeScript({ target: { tabId: tab.id },
    func: () => chrome.runtime.sendMessage({ notice: 'state' }).then(() => 'sent', (e) => 'sent: ' + e.message) });
  return got.result;
})()"""
NOTICE_FROM_THE_BACKGROUND = "chrome.runtime.sendMessage({ notice: 'state' }).then(() => 'sent', () => 'sent')"
RUN = {}


def setUpModule():
    RUN["start"] = time.time()


def tearDownModule():
    driver.check_keychain_log(RUN["start"])  # LD-276: no keychain write by a PID of the run


def open_popup(chrome, extension_id, shown=None, timeout=10):
    """Opens the toolbar popup as a click would (action.openPopup, from the service worker) and attaches to
    it; with `shown`, waits until it draws that frame."""
    url = "chrome-extension://%s/%s" % (extension_id, POPUP)
    worker = chrome.worker(extension_id)
    # A worker that answers may not have its extension API yet (seen once: "chrome is not defined").
    ext.wait_for(lambda: worker.eval("typeof chrome") == "object", timeout)
    got = worker.eval("chrome.action.openPopup().then(() => 'opened', (e) => String(e))")
    if got != "opened":
        raise AssertionError("action.openPopup: %s" % got)
    target = ext.wait_for(lambda: next((i["targetId"] for i in chrome.send("Target.getTargets")["targetInfos"]
                                        if i["url"] == url), None), timeout)
    if not target:
        raise AssertionError("no popup target")
    popup = chrome.attach(target)
    popup.send("Page.enable")
    if shown:
        wait_shown(popup, shown, timeout)
    return popup


def wait_shown(popup, frame, timeout=10):
    got = ext.wait_for(lambda: popup.eval("document.body.dataset.shown || ''") == frame, timeout)
    if not got:
        raise AssertionError("the popup shows %r, not %r" % (popup.eval("document.body.dataset.shown || ''"), frame))


def popup_gone(chrome, extension_id):
    url = "chrome-extension://%s/%s" % (extension_id, POPUP)
    return all(i["url"] != url for i in chrome.send("Target.getTargets")["targetInfos"])


def message(page, name, *subs):
    return page.eval("chrome.i18n.getMessage(%s, %s)" % (json.dumps(name), json.dumps(list(subs))))


class PopupWithLarsal(unittest.TestCase):
    """One headless Chrome with the development package; the popup over the test Larsal, in steps."""

    @classmethod
    def setUpClass(cls):
        for program in (ext.BRIDGE, ext.LARSAL):
            if not os.access(program, os.X_OK):
                raise AssertionError("missing %s: build it first (see test_extension.py)" % program)
        cls.folder = tempfile.mkdtemp(prefix="larsal-popup-", dir="/tmp")
        cls.home = driver.check_test_home(os.path.join(cls.folder, "home"))
        cls.instance = os.path.join(cls.folder, "i")
        os.makedirs(cls.home)
        os.makedirs(cls.instance, 0o700)
        cls.pkg = ext.test_package(cls.folder, "short-wait")
        cls.bridge_pids = os.path.join(cls.folder, "bridge-pids")
        cls.quick_pids = os.path.join(cls.folder, "quick-pids")
        cls.proxy_pids = os.path.join(cls.folder, "proxy-pids")  # test_extension.PROXY, and the larsal-bridge it starts
        cls.proxied_pids = os.path.join(cls.folder, "proxied-pids")
        cls.plan_file = os.path.join(cls.folder, "proxy-plan")
        cls.proxy_log_file = os.path.join(cls.folder, "proxy-log")
        cls.relay = ext.write_script(cls.home, "relay.sh", 'echo $$ >> "%s"\nLARSAL_TEST_INSTANCE_DIR="%s" exec "%s" "$@"\n'
                                     % (cls.bridge_pids, cls.instance, ext.BRIDGE))
        cls.quick = ext.write_script(cls.home, "quick.sh", 'echo $$ >> "%s"\nexit 0\n' % cls.quick_pids)
        cls.larsal = cls.popup = None
        cls.sites = driver.TestSites(cls.folder)
        cls.site = cls.sites.url("site-a.test", "/")
        cls.chrome = None
        try:
            cls.chrome = driver.Chrome(sites=cls.sites, home=cls.home)
            ext.setup_host(cls.home, cls.quick)  # first no Larsal at all: a host that exits at once
            cls.id = cls.chrome.load_extension(cls.pkg)
            cls.chrome.open(cls.site)  # a tab, as when the user clicks the toolbar icon on a page
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        problems = []
        if cls.larsal:
            cls.larsal.stop()
        for pid in cls.host_pids() + ext.pid_log(cls.quick_pids):
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
        outside = ext.outside_loopback(self.chrome.pids() + self.host_pids())
        if outside:
            self.chrome._kill()  # Chrome's PID, the one the driver started
            self.fail("STOP: a process of the run reached beyond loopback: %s" % outside)

    @classmethod
    def host_pids(cls):
        return (ext.pid_log(cls.bridge_pids) + ext.pid_log(cls.proxy_pids) + ext.pid_log(cls.proxied_pids))

    def start_larsal(self, enabled=True):
        with open(os.path.join(self.instance, "settings.json"), "w") as f:
            json.dump({"browser.enabled": enabled}, f)  # S-BRW-01 in the test settings file
        type(self).larsal = ext.Larsal(self.instance, self.site, self.home)
        return self.larsal

    def stop_larsal(self):
        self.larsal.stop()
        type(self).larsal = None

    def show(self, frame=None):
        type(self).popup = open_popup(self.chrome, self.id, frame)
        return self.popup

    def marks(self):
        return self.popup.eval("[0, 1, 2].map((i) => document.getElementById('mark-' + i).dataset.mark)")

    def click(self, element):
        self.popup.eval("document.getElementById(%s).click(); 1" % json.dumps(element), gesture=True)

    def test_01_with_no_host_the_popup_shows_not_reachable_with_the_first_check_failed(self):
        # INT-11.23, INT-11.24: no host (it exits at once) → not reachable, marks failed, unknown, unknown;
        # no hello was ever answered, so the first hint is MI11-04 b.
        self.assertEqual(self.id, build.DEV_ID)
        popup = self.show("not-reachable")
        self.assertEqual(self.marks(), ["failed", "unknown", "unknown"])
        self.assertEqual(popup.eval("document.getElementById('hint-0').textContent"),
                         message(popup, "MI11_04_b", "Chrome"))
        self.assertEqual(popup.eval(SHOWN_TEXT), [
            message(popup, "MI11_01"), message(popup, "MI11_02"), message(popup, "MI11_03"),
            message(popup, "MI11_04_b", "Chrome"), message(popup, "MI11_05"), message(popup, "MI11_06"),
            message(popup, "MI11_07", "Chrome"), message(popup, "MI11_08"), message(popup, "MI11_09"),
            message(popup, "MI11_10")])
        self.assertEqual(popup.eval(FROM_MESSAGES), [])

    def test_02_with_larsal_not_running_the_marks_change_on_try_again(self):
        # INT-11.24: Try Again (MI11-09) says hello now: larsal-bridge answers 44 → done, failed, unknown;
        # then Larsal with Browser Integration off answers 45 → done, done, failed.
        ext.setup_host(self.home, self.relay)
        self.popup.eval("window.marker = 'same document'; 1")
        self.click("try")
        self.assertTrue(ext.wait_for(lambda: self.marks() == ["done", "failed", "unknown"], 10), self.marks())
        self.start_larsal(enabled=False)
        self.click("try")
        self.assertTrue(ext.wait_for(lambda: self.marks() == ["done", "done", "failed"], 10), self.marks())
        self.assertEqual(self.popup.eval("window.marker"), "same document")
        self.stop_larsal()

    def test_03_once_larsal_starts_the_open_popup_changes_frame_without_a_reload(self):
        # INT-11.8, INT-11.24 last line: the open popup holds its "page" port, the background says hello each
        # second while Larsal answers 44, and the popup changes frame once Larsal is reached: the first
        # connection (check gives 8). The same document: no reload.
        self.click("try")
        self.assertTrue(ext.wait_for(lambda: self.marks() == ["done", "failed", "unknown"], 10), self.marks())
        larsal = self.start_larsal()
        wait_shown(self.popup, "first-connection", 10)
        self.assertEqual(self.popup.eval("window.marker"), "same document")
        larsal.wait(r"^question \d+ connect ")  # the frame sends `connect` when it shows (INT-11.25)

    def test_04_the_first_connection_shows_larsals_words_until_its_dialog_is_answered(self):
        # INT-11.25, INT-11.39: the popup's four words are the ones Larsal's dialog shows; MI11-13 while it is
        # open; the frame stays until Larsal's dialog (the test seam) is answered, then INT-11.23's next frame.
        question = self.larsal.wait(r"^question (\d+) connect (.+)$")
        words = self.popup.eval("[...document.getElementById('words').children].map((s) => s.textContent)")
        self.assertEqual(words, question.group(2).split()[-4:])  # "Check that the extension shows: w1 w2 w3 w4"
        self.assertEqual(len(words), 4)
        self.assertEqual(self.popup.eval(SHOWN_TEXT), [
            message(self.popup, "MI11_11", "Chrome"), message(self.popup, "MI11_12"), *words,
            message(self.popup, "MI11_13"), message(self.popup, "MI11_14")])
        time.sleep(ext.SHORT_WAIT + 1)  # past the wait: a connect waits for the user (T21)
        self.assertEqual(self.popup.eval("document.body.dataset.shown"), "first-connection")
        self.assertEqual(len([line for line in self.larsal.lines if line.startswith("question ")]), 1)
        self.larsal.say("allow %s Chrome on Test Mac" % question.group(1))
        wait_shown(self.popup, "ready", 10)

    def test_05_the_locked_frame_sends_unlock_and_nothing_else(self):
        # INT-11.26, B8: Larsal's notice makes the popup read again (the vault locked); the button sends
        # `unlock` with no field at all; Larsal's error 1 (no unlock panel) shows MI11-103 in one line, and
        # the frame changes once Larsal says the vault is open.
        self.larsal.say("lock")
        wait_shown(self.popup, "locked", 10)
        self.assertEqual(self.popup.eval(SHOWN_TEXT), [
            message(self.popup, "MI11_15", "demo-vault"), message(self.popup, "MI11_16"), message(self.popup, "MI11_19")])
        worker = self.chrome.worker(self.id)
        worker.eval(RECORD_BOXES)
        try:
            mark = self.larsal.mark()
            self.click("unlock")
            self.larsal.wait(r"^reply unlock error 1$", mark)
            self.assertTrue(ext.wait_for(lambda: self.popup.eval("!document.getElementById('unlock-refused').hidden"), 10))
            sealed = worker.eval("globalThis.sealed")
        finally:
            worker.eval("delete crypto.subtle.encrypt; 1")
        self.assertEqual(sealed[0], {"type": "unlock", "req": sealed[0]["req"]})  # no field: no password
        self.assertEqual([s["type"] for s in sealed[1:]], ["check", "status"])  # then INT-11.26's read again
        requests = [line.split()[1] for line in self.larsal.since(mark) if line.startswith("request ")]
        self.assertEqual(requests[0], "unlock")
        self.assertEqual(requests.count("unlock"), 1)
        self.assertEqual(self.popup.eval("document.getElementById('unlock-refused').textContent"),
                         message(self.popup, "MI11_103", "demo-vault"))
        self.larsal.say("unlock")
        wait_shown(self.popup, "ready", 10)

    def test_06_cancel_closes_the_popup_and_the_next_one_asks_once_on_a_new_session(self):
        # INT-11.25: a new Larsal (no connection: check gives 8); Cancel closes the popup and ends the session
        # (a new hello replaces it); the next popup sends one new connect, with new words.
        self.popup.eval("window.close(); 1")
        self.assertTrue(ext.wait_for(lambda: popup_gone(self.chrome, self.id), 5))
        self.stop_larsal()
        larsal = self.start_larsal()
        self.show("first-connection")
        first = larsal.wait(r"^question (\d+) connect (.+)$")
        sessions = larsal.mark()
        self.click("cancel")
        self.assertTrue(ext.wait_for(lambda: popup_gone(self.chrome, self.id), 5))
        larsal.wait(r"^reply connect error 6$", sessions)  # the hello replaced the session: Deny (INT-01.20)
        mark = larsal.mark()
        self.show("first-connection")
        second = larsal.wait(r"^question (\d+) connect (.+)$", mark)
        self.assertNotEqual(second.group(2), first.group(2))
        words = self.popup.eval("[...document.getElementById('words').children].map((s) => s.textContent)")
        self.assertEqual(words, second.group(2).split()[-4:])
        time.sleep(1)
        self.assertEqual(len([line for line in larsal.since(mark) if line.startswith("question ")]), 1)
        type(self).question = second  # still open: test_07 answers it

    def test_07_larsals_deny_shows_mi11_61_with_try_again(self):
        # INT-11.25: error 6 → MI11-61 with Try Again in place of a new connect; Try Again asks once more.
        question = self.question
        mark = self.larsal.mark()
        self.larsal.say("deny %s" % question.group(1))
        self.assertTrue(ext.wait_for(lambda: self.popup.eval("!document.getElementById('refused').hidden"), 10))
        self.assertEqual(self.popup.eval(SHOWN_TEXT), [
            message(self.popup, "MI11_11", "Chrome"), message(self.popup, "MI11_12"),
            *question.group(2).split()[-4:], message(self.popup, "MI11_61"), message(self.popup, "MI11_09"),
            message(self.popup, "MI11_14")])
        time.sleep(1)
        self.assertEqual([line for line in self.larsal.since(mark) if line.startswith("question ")], [])
        self.click("again")
        again = self.larsal.wait(r"^question (\d+) connect ", mark)
        self.assertTrue(ext.wait_for(lambda: self.popup.eval("document.getElementById('refused').hidden"), 10))
        self.larsal.say("allow %s Chrome on Test Mac" % again.group(1))
        wait_shown(self.popup, "ready", 10)
        self.assertEqual(self.popup.eval(FROM_MESSAGES), [])

    def requests_since(self, mark):
        return [line.split()[1] for line in self.larsal.since(mark) if line.startswith("request ")]

    def test_08_only_the_backgrounds_notice_makes_the_popup_read_again(self):
        # The popup takes a state notice only from this extension's background (sender.id is the extension's,
        # no tab): one a content script sends changes nothing; the background's makes it read check and status.
        worker = self.chrome.worker(self.id)
        mark = self.larsal.mark()
        self.assertTrue(worker.eval(NOTICE_FROM_A_PAGE).startswith("sent"))
        time.sleep(1.5)
        self.assertEqual(self.requests_since(mark), [])
        self.assertEqual(worker.eval(NOTICE_FROM_THE_BACKGROUND), "sent")
        self.larsal.wait(r"^reply status ok$", mark)
        self.assertEqual(self.requests_since(mark), ["check", "status"])

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

    def test_09_after_a_plain_4_the_open_popup_comes_back_by_itself(self):
        # INT-11.10, INT-11.8: Chrome's host is now test_extension's PROXY (larsal-bridge behind a relay). A plain
        # 4 to the open popup's own check shows not reachable; the background's new hello then reaches Larsal and
        # tells the pages, so the same popup draws the ready frame again with no click: one notice when the state
        # reads found Larsal not reachable, one when they found it again (both ways).
        program = driver.inside(self.home, "proxy.py")
        with open(program, "w") as f:
            f.write(ext.PROXY)
        ext.setup_host(self.home, ext.write_script(
            self.home, "proxy.sh", 'echo $$ >> "%s"\nLARSAL_TEST_INSTANCE_DIR="%s" exec "%s" -B -I %s "$@"\n' % (
                self.proxy_pids, self.instance, sys.executable, " ".join('"%s"' % p for p in (
                    program, self.plan_file, self.proxy_log_file, self.proxied_pids, ext.BRIDGE)))))
        mark = self.larsal.mark()
        os.kill(ext.pid_log(self.bridge_pids)[-1], signal.SIGTERM)  # the port closes; the reconnect reaches PROXY
        self.larsal.wait(r"^reply status ok$", mark)
        self.assertEqual(self.proxy_log(), ["hello pass", "box pass", "box pass"])  # hello, check, status
        wait_shown(self.popup, "ready", 5)
        self.assertEqual(self.popup.eval(WATCH_FRAMES), 1)
        self.plan(4)
        seen = len(self.proxy_log())
        self.assertEqual(self.chrome.worker(self.id).eval(NOTICE_FROM_THE_BACKGROUND), "sent")
        self.assertTrue(ext.wait_for(lambda: "not-reachable" in self.popup.eval("window.shownLog"), 10),
                        self.popup.eval("window.shownLog"))
        wait_shown(self.popup, "ready", 10)
        time.sleep(1.5)
        log = self.popup.eval("window.shownLog")
        self.assertEqual(log[log.index("not-reachable"):][-1], "ready")
        self.assertEqual(self.popup.eval("document.body.dataset.shown"), "ready")
        self.assertEqual(self.popup.eval("window.marker"), "same document")
        self.assertEqual(self.popup.eval("window.notices"), 3)  # the test's, then the background's two
        self.assertEqual(self.proxy_log()[seen:seen + 2], ["box 4", "hello pass"])

    def test_10_a_second_unlock_while_one_waits_sends_nothing(self):
        # INT-11.26, INT-01.44: at most one `unlock` waits, as for `connect`. PROXY holds the unlock's box for
        # 6 seconds (Larsal's unlock panel open); eight clicks meanwhile send one unlock, and check and status
        # still answer; then Larsal's reply (error 1: no unlock panel) reaches every click.
        mark = self.larsal.mark()
        self.larsal.say("lock")
        wait_shown(self.popup, "locked", 10)
        self.larsal.wait(r"^reply status ok$", mark)
        worker = self.chrome.worker(self.id)
        worker.eval(RECORD_BOXES)
        try:
            time.sleep(0.5)
            mark = self.larsal.mark()
            self.plan(["late", 6, "pass"])
            for _ in range(8):
                self.click("unlock")
            time.sleep(1)
            start = time.monotonic()
            got = self.popup.eval("chrome.runtime.sendMessage({ route: 'popup.status' })")
            self.assertLess(time.monotonic() - start, 4)  # not queued behind waiting unlocks
            self.assertEqual((got["reach"], got["status"]["vaults"][0]["state"]), ("ok", "locked"))
            self.assertEqual(self.requests_since(mark), ["check", "status"])  # the unlock is still held
            self.larsal.wait(r"^reply unlock error 1$", mark, timeout=15)
            sealed = worker.eval("globalThis.sealed")
        finally:
            worker.eval("delete crypto.subtle.encrypt; 1")
        self.assertEqual([s["type"] for s in sealed].count("unlock"), 1)
        self.assertEqual(self.requests_since(mark).count("unlock"), 1)
        self.assertTrue(ext.wait_for(lambda: self.popup.eval("!document.getElementById('unlock-refused').hidden"), 10))
        self.larsal.say("unlock")
        wait_shown(self.popup, "ready", 10)


class PopupParity(unittest.TestCase):
    """The three frames from demo states, light and dark, against design/option-a/mockup.html (no host)."""

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp(prefix="larsal-parity-", dir="/tmp")
        cls.addClassCleanup(shutil.rmtree, cls.folder, True)
        cls.out = os.environ.get("LARSAL_PARITY_DIR") or os.path.join(cls.folder, "parity")
        os.makedirs(cls.out, exist_ok=True)
        cls.home = driver.check_test_home(os.path.join(cls.folder, "home"))
        os.makedirs(cls.home)
        pkg = ext.test_package(cls.folder, "fed-state")
        sites = os.path.join(cls.folder, "sites")
        os.makedirs(sites)
        os.symlink(MOCKUP, os.path.join(sites, "site-a.test"))  # the mockup over the demo https server
        cls.sites = driver.TestSites(cls.folder, root=sites)
        cls.addClassCleanup(cls.sites.close)
        cls.chrome = driver.Chrome(sites=cls.sites, home=cls.home)
        cls.addClassCleanup(cls.chrome.close)  # fails on a guard hit, a focus change or a changed owner file
        cls.id = cls.chrome.load_extension(pkg)
        cls.tab = cls.chrome.open("about:blank", 1600, 1000)
        cls.rows = []

    @classmethod
    def tearDownClass(cls):
        rows = ["| Frame | Theme | Popup (px) | Mockup (px) | Changed pixels | % | Parts with equal tokens (item 3) "
                "| Largest box offset, pt (item 4) | Controls in tab order (item 7) | Result |",
                "|---|---|---|---|---|---|---|---|---|---|"]
        rows += ["| %s | %s | %s | %s | %d of %d | %.3f | %s | %s | %s | %s |" % r for r in cls.rows]
        with open(os.path.join(cls.out, "PARITY.md"), "w") as f:
            f.write("# Popup parity, E7-S7d\n\nThe popup drawn from demo states in headless Chrome, against the same "
                    "frame of design/option-a/mockup.html in the same Chrome (BUILD-AND-VERIFY.md items 3, 4, 5 and 7). "
                    "Item 5: pixelmatch's YIQ delta, threshold 0.1, anti-aliasing counted; over 3 % fails. Item 3: "
                    "every part the frame draws (each text run, button, icon, and painted box such as the tile, the "
                    "checks' box and its rules, and the word chips) with its colours, edges, corners and font, "
                    "matched by its words or its order. Item 4: each part's box relative to the panel within 2 pt. "
                    "Item 7: each control's accessible name (DOM and Chrome's accessibility tree) is its message, "
                    "tab order runs top to bottom as in the mockup; known difference: MI11-20 (\"Other vaults\") is "
                    "a line with no action, not a control, until E7-S7f (D-INT11-3).\n\n"
                    + "\n".join(rows) + "\n")

    def tearDown(self):
        self.assertEqual(ext.outside_loopback(self.chrome.pids()), [])

    def popup(self, state, dark):
        popup = open_popup(self.chrome, self.id)
        popup.send("Emulation.setEmulatedMedia", {"features": [
            {"name": "prefers-color-scheme", "value": "dark" if dark else "light"}]})
        popup.eval("document.fonts.ready.then(() => 1)")
        popup.eval("window.fed = %s; window.redraw()" % json.dumps(state))
        return popup

    def shot(self, session, selector, path):
        session.eval("document.fonts.ready.then(() => 1)")
        time.sleep(0.3)
        box = session.eval("(() => { const r = document.querySelector(%s).getBoundingClientRect();"
                           " return [r.x + scrollX, r.y + scrollY, r.width, r.height]; })()" % json.dumps(selector))
        data = session.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True, "clip": {
            "x": box[0], "y": box[1], "width": box[2], "height": box[3], "scale": 1}})["data"]
        with open(path, "wb") as f:
            f.write(base64.b64decode(data))
        return "data:image/png;base64," + data

    def mockup(self, title, dark):
        self.tab.navigate(self.sites.url("site-a.test", "/mockup.html?only=extension%s" % ("&theme=dark" if dark else "")))
        found = self.tab.eval("(() => { const f = [...document.querySelectorAll('figure.frame')].find((e) => "
                              "e.querySelector('figcaption b').textContent === %s); if (!f) return null;"
                              " f.id = 'parity-frame'; f.scrollIntoView(); return 1; })()" % json.dumps(title))
        self.assertEqual(found, 1, title)
        self.assertEqual(self.tab.eval("getComputedStyle(document.querySelector('#parity-frame .zoom'))"
                                       ".getPropertyValue('--z').trim()"), "1")
        return "#parity-frame .xp"

    def compare(self, frame, dark):
        title, state = FED[frame]
        theme = "dark" if dark else "light"
        popup = self.popup(state, dark)
        try:
            wait_shown(popup, {"extension-popup-app-not-reachable": "not-reachable",
                               "extension-popup-first-connection": "first-connection",
                               "extension-popup-vault-locked": "locked"}[frame])
            a = self.shot(popup, ".xp", os.path.join(self.out, "%s-%s-popup.png" % (frame, theme)))
            mine = popup.eval(SPEC % "document.querySelector('[data-frame]:not([hidden])'), document.body, "
                                     "document.querySelector('.xp')")
            controls = popup.eval(CONTROLS)
            ax = popup.send("Accessibility.getFullAXTree")["nodes"]
            label, line = message(popup, "MI11_101_a"), message(popup, "MI11_20", "Work, Family")  # FED's other vaults
        finally:
            popup.eval("window.close(); 1")
            ext.wait_for(lambda: popup_gone(self.chrome, self.id), 5)
        where = self.mockup(title, dark)  # the screenshot's resize redraws the board: read the parts first
        theirs = self.tab.eval(SPEC % ", ".join(["document.querySelector('#parity-frame .xp')"] * 3))
        buttons = self.tab.eval("[...document.querySelectorAll('#parity-frame .xp button')].map((b) => b.textContent.trim())")
        b = self.shot(self.tab, where, os.path.join(self.out, "%s-%s-mockup.png" % (frame, theme)))
        got = self.tab.eval(COMPARE % {"a": json.dumps(a), "b": json.dumps(b)}, timeout=60)
        with open(os.path.join(self.out, "%s-%s-diff.png" % (frame, theme)), "wb") as f:
            f.write(base64.b64decode(got["diff"]))
        share = 100 * got["changed"] / got["total"]
        # Item 3: the same parts with the same colours and fonts; item 4: each box within 2 pt.
        tokens = [k for k in theirs if k in mine and mine[k]["style"] == theirs[k]["style"]]
        off = {k: max(abs(p - q) for p, q in zip(mine[k]["box"], theirs[k]["box"]))
               for k in theirs if k in mine and "box" in theirs[k]}
        far = sorted(k for k, d in off.items() if d > GEOMETRY)
        # Item 7: each control's name is its message; tab order is the frame's order, top to bottom, left to right,
        # and the mockup's controls in its order, but for MI11-20, a line with no action until E7-S7f (D-INT11-3).
        names = [c["name"] for c in controls]
        named = [n["name"]["value"] for n in ax if not n.get("ignored") and n.get("role", {}).get("value") == "button"]
        dialog = [n["name"]["value"] for n in ax if not n.get("ignored") and n.get("role", {}).get("value") == "dialog"]
        access = ([c for c in controls if c["name"] != c["message"] or c["tabindex"] != 0] == []
                  and [c["at"] for c in controls] == sorted(c["at"] for c in controls)
                  and names == [t for t in buttons if t != line] and sorted(named) == sorted(names)
                  and dialog == [label])
        ok = (share <= 3 and got["a"] == got["b"] and len(tokens) == len(theirs) and set(mine) == set(theirs)
              and not far and access)
        self.rows.append((frame, theme, "%d×%d" % tuple(got["a"]), "%d×%d" % tuple(got["b"]), got["changed"],
                          got["total"], share, "%d equal of %d" % (len(tokens), len(theirs)),
                          "%.1f" % max(off.values(), default=0), ", ".join(names) or "none",
                          "PASS" if ok else "FAIL"))
        self.assertEqual(sorted(mine), sorted(theirs), "%s %s: parts" % (frame, theme))
        self.assertEqual({k: mine[k]["style"] for k in theirs}, {k: theirs[k]["style"] for k in theirs},
                         "%s %s: tokens" % (frame, theme))
        self.assertEqual(far, [], "%s %s: geometry over %d pt: %s" % (frame, theme, GEOMETRY, {
            k: (mine[k]["box"], theirs[k]["box"]) for k in far}))
        self.assertEqual([(c["name"], c["tabindex"]) for c in controls], [(c["message"], 0) for c in controls])
        self.assertEqual([c["at"] for c in controls], sorted(c["at"] for c in controls), "tab order")
        self.assertEqual(names, [t for t in buttons if t != line], "%s %s: the mockup's controls" % (frame, theme))
        self.assertEqual(sorted(named), sorted(names), "accessible buttons")
        self.assertEqual(dialog, [label])
        self.assertEqual(got["a"], got["b"], "%s %s: sizes" % (frame, theme))
        self.assertLessEqual(share, 3, "%s %s" % (frame, theme))

    def test_not_reachable_light(self):
        self.compare("extension-popup-app-not-reachable", False)

    def test_not_reachable_dark(self):
        self.compare("extension-popup-app-not-reachable", True)

    def test_first_connection_light(self):
        self.compare("extension-popup-first-connection", False)

    def test_first_connection_dark(self):
        self.compare("extension-popup-first-connection", True)

    def test_vault_locked_light(self):
        self.compare("extension-popup-vault-locked", False)

    def test_vault_locked_dark(self):
        self.compare("extension-popup-vault-locked", True)

    def test_open_larsal_asks_for_larsals_url_and_nothing_else(self):
        # D-INT11-1 (a), MI11-10: in the not-reachable frame and the no-vault line, Open Larsal opens Larsal's one
        # URL with tabs.create and does nothing else. Every way out is stubbed first, so nothing opens.
        for state, frame in (({"reach": 44}, "not-reachable"),
                             ({"reach": "ok", "status": {"vaults": []}, "check": {"error": 8}}, "no-vault")):
            popup = self.popup(state, False)
            try:
                wait_shown(popup, frame)
                self.assertEqual(popup.eval(WATCH), 1, "a stub did not take: nothing is clicked")
                popup.eval("document.querySelector('[data-frame=%s] [data-msg=MI11_10]').click(); 1"
                           % json.dumps(frame), gesture=True)
                time.sleep(0.5)
                self.assertEqual(popup.eval("window.asked"), [["tabs.create", {"url": "app.larsal.desktop://open"}]])
            finally:
                popup.eval("window.close(); 1")
                ext.wait_for(lambda: popup_gone(self.chrome, self.id), 5)

    def test_other_states_draw_their_messages(self):
        # INT-11.5 (MI11-60, no checks, no buttons), INT-11.23 (MI11-64 with Open Larsal), INT-11.24 (45),
        # INT-11.25 (MI11-61 after a Deny kept by the background), INT-11.26 (MI11-20 only with other vaults).
        cases = [
            ({"reach": "too-old"}, "not-reachable", ["MI11_01", ("MI11_60", "Chrome", "133")]),
            ({"reach": "ok", "status": {"vaults": []}, "check": {"error": 8}}, "no-vault", ["MI11_64", "MI11_10"]),
            (dict(FED["extension-popup-first-connection"][1], connecting=False, refused=True), "first-connection",
             [("MI11_11", "Chrome"), "MI11_12", "harbor", "quill", "ember", "forty-two", "MI11_61", "MI11_09", "MI11_14"]),
            ({"reach": "ok", "check": {"error": 1}, "status": {"vaults": [dict(VAULT, state="locked")]}}, "locked",
             [("MI11_15", "Personal"), "MI11_16", "MI11_19"]),
        ]
        for state, frame, texts in cases:
            popup = self.popup(state, False)
            try:
                wait_shown(popup, frame)
                want = [t if t in ("harbor", "quill", "ember", "forty-two") else
                        message(popup, *(t if isinstance(t, tuple) else (t,))) for t in texts]
                self.assertEqual(popup.eval(SHOWN_TEXT), want, frame)
                self.assertEqual(popup.eval(FROM_MESSAGES), [])
            finally:
                popup.eval("window.close(); 1")
                ext.wait_for(lambda: popup_gone(self.chrome, self.id), 5)
        popup = self.popup({"reach": 45}, False)
        try:
            self.assertEqual(popup.eval("[0, 1, 2].map((i) => document.getElementById('mark-' + i).dataset.mark)"),
                             ["done", "done", "failed"])
        finally:
            popup.eval("window.close(); 1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
