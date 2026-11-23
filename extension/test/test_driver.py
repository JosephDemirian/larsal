"""Tests of the headless Chrome driver (story E7-S7b).

Run: python3 -I extension/test/test_driver.py
Needs the pinned test browser ($LARSAL_TEST_CHROME under driver.TEST_BROWSERS, see driver.py),
/usr/bin/openssl and Xcode's swiftc. No window, no network beyond 127.0.0.1, nothing outside
/tmp (AGENTS.md rules 7, 10, 11).
"""

import hashlib
import http.client
import io
import json
import os
import re
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import driver  # noqa: E402

PINNED = driver.MANIFEST_SHA256  # the driver's own pin (the real test browser's manifest), before a test changes it

DEMO = os.path.join(driver.HERE, "demo-extension")
CONNECT_ECHO = """new Promise((resolve) => {
  const port = chrome.runtime.connectNative('app.larsal.test.echo');
  port.onMessage.addListener((message) => { resolve(message); port.disconnect(); });
  port.onDisconnect.addListener(() => resolve({ error: chrome.runtime.lastError && chrome.runtime.lastError.message }));
  port.postMessage({ hello: 'echo' });
})"""
CREATE_PASSKEY = """navigator.credentials.create({ publicKey: {
  rp: { id: 'site-a.test', name: 'site-a.test' },
  user: { id: new Uint8Array([1, 2, 3, 4]), name: 'demo', displayName: 'Demo' },
  challenge: new Uint8Array(32).fill(7),
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
  authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
} }).then((c) => ({ type: c.type, client: JSON.parse(new TextDecoder().decode(c.response.clientDataJSON)) }))"""
# A stand-in test browser: it answers the driver's DevTools pipe (fd 3 in, fd 4 out) and does nothing else, so
# a rule can be seen to fail without a real browser running outside the sandbox.
FAKE_BROWSER = """#!%s -IB
import json, os
data = b""
while True:
    chunk = os.read(3, 65536)
    if not chunk:
        break
    data += chunk
    while b"\\0" in data:
        raw, data = data.split(b"\\0", 1)
        message = json.loads(raw)
        result = {"targetInfos": []} if message["method"] == "Target.getTargets" else {}
        os.write(4, json.dumps({"id": message["id"], "result": result}).encode() + b"\\0")
        if message["method"] == "Browser.close":
            raise SystemExit(0)
"""
# What a process may reach: each socket to a remote address is bound to lo0 (IP_BOUND_IF, 25), so no packet
# can leave this Mac even with no sandbox; 192.0.2.1 is TEST-NET-1 (RFC 5737). argv[1]: a folder to write in;
# argv[2]: the port of a loopback listener the test opens outside the sandbox, where nothing may listen. The bind
# on every interface never listens, so nothing could connect to it even with no sandbox.
NET_PROBE = """import errno, json, os, socket, sys
out = {}
for kind, family in (("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)):
    s = socket.socket(socket.AF_INET, family)
    s.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex("lo0"))
    s.settimeout(2)
    try:
        s.connect(("192.0.2.1", 443)) if kind == "tcp" else s.sendto(b"x", ("192.0.2.1", 53))
        out[kind] = "sent"
    except OSError as e:
        out[kind] = errno.errorcode.get(e.errno, str(e))
    s.close()
for kind, connect in (("resolver", lambda s: s.connect("/private/var/run/mDNSResponder")),
                      ("loopback", lambda s: s.connect(("127.0.0.1", int(sys.argv[2]))))):
    s = socket.socket(socket.AF_UNIX if kind == "resolver" else socket.AF_INET)
    try:
        connect(s)
        out[kind] = "connected"
    except OSError as e:
        out[kind] = errno.errorcode.get(e.errno, str(e))
    s.close()
for kind, host, listen in (("bind-any", "0.0.0.0", False), ("listen-loopback", "127.0.0.1", True)):
    s = socket.socket()
    try:
        s.bind((host, 0))
        if listen:
            s.listen(1)
        out[kind] = "bound"
    except OSError as e:
        out[kind] = errno.errorcode.get(e.errno, str(e))
    s.close()
try:
    open(os.path.join(sys.argv[1], "written"), "w").close()
    out["wall"] = "written"
except OSError as e:
    out["wall"] = errno.errorcode.get(e.errno, str(e))
print(json.dumps(out))
"""
# A lookup of each service named: no message is sent, so no service does anything. 0: found and allowed.
LOOKUP_PROBE = """import ctypes, json, sys
lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
port, out = ctypes.c_uint(0), {}
for name in sys.argv[1:]:
    out[name] = lib.bootstrap_look_up(ctypes.c_uint.in_dll(lib, "bootstrap_port"), name.encode(), ctypes.byref(port))
print(json.dumps(out))
"""
# Real writes inside a profile, each outside the owner's folders: argv[1] the run root (its home/ is the run's),
# argv[2] a folder beside it under /tmp, argv[3] a file in that folder.
WRITE_PROBE = """import errno, json, os, sys
root, beside, kept = sys.argv[1:4]
out = {}
def attempt(kind, act):
    try:
        act()
        out[kind] = "written"
    except OSError as e:
        out[kind] = errno.errorcode.get(e.errno, str(e))
attempt("create-own", lambda: open(os.path.join(root, "home", "written"), "x").close())
attempt("create-beside", lambda: open(os.path.join(beside, "written"), "x").close())
attempt("data-beside", lambda: open(kept, "a").write("x"))
attempt("unlink-beside", lambda: os.remove(kept))
attempt("dev-null", lambda: open("/dev/null", "w").write("x"))
print(json.dumps(out))
"""
# UDP connect() on a socket bound to lo0 (IP_BOUND_IF 25, IPV6_BOUND_IF 125): no packet is sent, the kernel and
# its sandbox only answer. Each argument: "<address> <port>".
UDP_PROBE = """import errno, json, socket, sys
out = {}
for spec in sys.argv[1:]:
    host, port = spec.rsplit(" ", 1)
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.setsockopt(*((socket.IPPROTO_IPV6, 125) if family == socket.AF_INET6 else (socket.IPPROTO_IP, 25)),
                 socket.if_nametoindex("lo0"))
    try:
        s.connect(socket.getaddrinfo(host, int(port), family, socket.SOCK_DGRAM, 0, socket.AI_NUMERICHOST)[0][4])
        out[spec] = "connected"
    except OSError as e:
        out[spec] = errno.errorcode.get(e.errno, str(e))
    s.close()
print(json.dumps(out))
"""
NO_REPORT, PATH_FILTER = 0x40000000, 1  # sandbox_check: SANDBOX_CHECK_NO_REPORT (nothing logged), a path
# Round 4 (C1R3-01): TCP connect() to "<address> <port>", each one a listener of the test on 127.0.0.1 or ::1 (or the
# IPv4-mapped form of 127.0.0.1), so even with no sandbox nothing leaves this Mac.
TCP_PROBE = """import errno, json, socket, sys
out = {}
for spec in sys.argv[1:]:
    host, port = spec.rsplit(" ", 1)
    s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET)
    s.settimeout(2)
    try:
        s.connect((host, int(port)))
        out[spec] = "connected"
    except OSError as e:
        out[spec] = errno.errorcode.get(e.errno, str(e))
    s.close()
print(json.dumps(out))
"""
# Round 4 (C2R3-02): unix-domain sockets: "connect <path>" to a listener of the test, "bind <path>" a new one.
UNIX_PROBE = """import errno, json, socket, sys
out = {}
for spec in sys.argv[1:]:
    kind, path = spec.split(" ", 1)
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(2)
    try:
        s.connect(path) if kind == "connect" else s.bind(path)
        out[spec] = "connected" if kind == "connect" else "bound"
    except OSError as e:
        out[spec] = errno.errorcode.get(e.errno, str(e))
    s.close()
print(json.dumps(out))
"""
# The connect events of a start as Chromium's NetLog writes them while it runs: the constants, then one event per
# line, the list not closed yet (C1R3-03, C2R3-05).
NETLOG = ('{"constants": {"logEventTypes": {"TCP_CONNECT": 1, "TCP_CONNECT_ATTEMPT": 2, "URL_REQUEST_START_JOB": 3}},\n'
          '"events": [\n'
          '{"type": 3, "time": "1", "phase": 1, "source": {"id": 7}, "params": {"url": "https://site-a.test/"}},\n'
          '{"type": 1, "time": "2", "phase": 1, "source": {"id": 8}, "params": {"address_list": ["127.0.0.1:8443"]}},\n'
          '{"type": 2, "time": "3", "phase": 1, "source": {"id": 8}, "params": {"address": "127.0.0.1:8443"}},\n'
          '{"type": 1, "time": "4", "phase": 2, "source": {"id": 8}, "params": {"net_error": -102}},\n')
NETLOG_CONNECTS = [{"address_list": ["127.0.0.1:8443"]}, {"address": "127.0.0.1:8443"}, {"net_error": -102}]


def own_addresses():
    """This Mac's own addresses, as ifconfig lists them (link-local ones with their interface): its LAN address too."""
    out = subprocess.run(["/sbin/ifconfig"], check=True, capture_output=True, text=True).stdout
    return sorted(set(re.findall(r"^\s+inet6? ([0-9a-f.:]+(?:%[0-9a-z]+)?) ", out, re.M)))


def denies_write(pid, operation, path):
    """True when the sandbox of process `pid` denies `operation` on `path` (sandbox_check only asks)."""
    return driver._SANDBOX_CHECK(pid, operation.encode(), PATH_FILTER | NO_REPORT, path.encode()) == 1


def sandboxed_sleep(case, profile=None):
    """A live /bin/sleep inside `profile` (the driver's default when None), stopped when the test ends."""
    sleeper = subprocess.Popen(driver.sandboxed(["/bin/sleep", "30"], profile))
    case.addCleanup(sleeper.wait)
    case.addCleanup(sleeper.kill)  # our own child
    deadline = time.monotonic() + 10
    while not driver.command_line(sleeper.pid).startswith("/bin/sleep") and time.monotonic() < deadline:
        time.sleep(0.05)  # sandbox-exec applies the profile, then execs sleep
    return sleeper


RUN = {}


def setUpModule():
    RUN["start"] = time.time()


def tearDownModule():
    # LD-276, LD-278 (3): after the suite run, macOS's own log shows no keychain write by a PID of the run; and no
    # late crash report, menu bar item or location registration of the run (round 2: F1, F2, F5).
    driver.check_run_end(RUN["start"])


def temp_folder(case):
    folder = driver.run_root("larsal-driver-test-")  # round 4 (C1R3-06): a run root this driver process made
    case.addCleanup(shutil.rmtree, folder, True)
    return folder


def drop_kept(case, chrome):
    """Round 4 (C1R3-03): removes, when the test ends, the connect files `chrome` keeps from here on for the page
    loads the test fails on purpose (an unexpected failure's file stays, named in its error)."""
    first = len(chrome.kept)

    def drop():
        for _, path in chrome.kept[first:]:
            shutil.rmtree(os.path.dirname(path), True)
        del chrome.kept[first:]
    case.addCleanup(drop)


def drop_kept_in(case, error):
    """The same for a start the test fails on purpose: its connect file is named in the error."""
    for path in re.findall(r"socket connects of this start: (\S+)\)", str(error)):
        case.addCleanup(shutil.rmtree, os.path.dirname(path), True)


def lstat_tree(top):
    """(inode, size, modification time) of `top` and of every entry under it, by path; None for a missing one."""
    found = {}
    for parent, dirs, files in os.walk(top):
        for name in dirs + files:
            s = os.lstat(os.path.join(parent, name))
            found[os.path.join(parent, name)] = (s.st_ino, s.st_size, s.st_mtime_ns)
    try:
        s = os.lstat(top)
        found[top] = (s.st_ino, s.st_size, s.st_mtime_ns)
    except FileNotFoundError:
        found[top] = None
    return found


def wall_paths(walls, notes):
    """C1R3-07: the path to ask sandbox_check for each wall: the wall, or for a missing one its nearest existing
    parent (sandbox_check reads any missing path as denied, so a missing wall itself proves nothing; a rule that
    denies the parent denies everything under it but the run's own folders). Each substitution goes into `notes`."""
    asked = []
    for wall in walls:
        path = wall
        while not os.path.lexists(path):
            path = os.path.dirname(path)
        if path != wall:
            notes.append("%s is missing here: asked its nearest existing parent %s" % (wall, path))
        asked.append(path)
    return asked


def tcp_listeners(case):
    """A port with a TCP listener of this test on 127.0.0.1 and one on ::1, closed when the test ends."""
    while True:
        four, six = socket.socket(), socket.socket(socket.AF_INET6)
        four.bind(("127.0.0.1", 0))
        six.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            six.bind(("::1", four.getsockname()[1]))
        except OSError:  # that port is taken on ::1: another one
            four.close()
            six.close()
            continue
        for s in (four, six):
            s.listen(16)
            case.addCleanup(s.close)
        return four.getsockname()[1]


# Round 4: ports on which the old rule order (the port's allow before the unix-socket lines) refused TCP, in run
# folders named larsal-chrome-* and larsal-ext-* (r4/probes/tcp-ports-1.json, tcp-sweep-1.json, tcp-profiles-1.json,
# and extension-1's second try).
REFUSED_BEFORE = (54824, 55592, 55715, 56019, 56953, 57113, 57806, 57888, 58043, 58473, 59023, 59209, 59259)


def listen_on(case, port):
    """A TCP listener of this test on 127.0.0.1:port and one on ::1:port, closed when the test ends; False when
    either address is taken."""
    four, six = socket.socket(), socket.socket(socket.AF_INET6)
    six.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    try:
        four.bind(("127.0.0.1", port))
        six.bind(("::1", port))
    except OSError:
        four.close()
        six.close()
        return False
    for s in (four, six):
        s.listen(16)
        case.addCleanup(s.close)
    return True


def fake_guard(case, before, after):
    """A stand-in window guard: "ready <PID in the file before>" when it starts and "done <PID in the file after>"
    when its input closes (the frontmost app as the real guard reports it), and nothing else."""
    fake = os.path.join(temp_folder(case), "guard")
    with open(fake, "w") as f:
        f.write('#!/bin/sh\necho ready "$(cat "%s")" false\nread line\necho done "$(cat "%s")" 1\n' % (before, after))
    os.chmod(fake, 0o700)
    return fake


def fake_browser(case, files=None, links=None, binary="app/browser"):
    """FAKE_BROWSER at <folder>/<binary>, named with its SHA-256 by <folder>/MANIFEST.json, which also names
    every other file (`files`, path: text) and link (`links`, path: target) of its app, as the real one does.
    For this test only, <folder> is the test browsers' folder and its manifest the pinned one (pin)."""
    folder, path = temp_folder(case), binary
    binary = os.path.join(folder, path)
    os.makedirs(os.path.dirname(binary))
    with open(binary, "w") as f:
        f.write(FAKE_BROWSER % sys.executable)
    os.chmod(binary, 0o700)
    for name, text in (files or {}).items():
        os.makedirs(os.path.dirname(os.path.join(folder, name)), exist_ok=True)
        with open(os.path.join(folder, name), "w") as f:
            f.write(text)
    for name, target in (links or {}).items():
        os.symlink(target, os.path.join(folder, name))
    recorded = {}
    for name in [path] + list(files or {}):
        with open(os.path.join(folder, name), "rb") as f:
            recorded[name] = hashlib.sha256(f.read()).hexdigest()
    with open(os.path.join(folder, driver.MANIFEST), "w") as f:
        json.dump({"binary": {"path": path, "sha256": recorded[path]}, "files": recorded,
                   "links": dict(links or {})}, f)
    pin(case, folder)
    return binary


def pin(case, folder):
    """Round 3 (C2-12): the driver starts a browser only from TEST_BROWSERS, and only under the manifest whose
    SHA-256 it pins. For this test only, `folder` is that place and its MANIFEST.json, as it is now, that one."""
    with open(os.path.join(folder, driver.MANIFEST), "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    for name, value in (("TEST_BROWSERS", folder), ("MANIFEST_SHA256", digest)):
        patch = mock.patch.object(driver, name, value)
        patch.start()
        case.addCleanup(patch.stop)


def probe(argv):
    return json.loads(subprocess.run(argv, check=True, capture_output=True, text=True).stdout)


class HeadlessChromeTests(unittest.TestCase):
    """One Chrome with the demo extension and the test sites."""

    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.mkdtemp(prefix="larsal-driver-test-", dir="/tmp")
        cls.addClassCleanup(shutil.rmtree, cls.folder, True)
        cls.sites = driver.TestSites(cls.folder)
        cls.addClassCleanup(cls.sites.close)
        cls.chrome = driver.Chrome(sites=cls.sites)
        cls.addClassCleanup(cls.chrome.close)  # fails on a guard hit, a focus change or a changed owner file
        cls.extension = cls.chrome.load_extension(DEMO)

    def test_demo_extension_of_two_files_loads_and_its_id_comes_back(self):
        self.assertEqual(sorted(os.listdir(DEMO)), ["background.js", "manifest.json"])
        self.assertRegex(self.extension, r"^[a-p]{32}$")

    def test_service_worker_answers_a_message(self):
        page = self.chrome.open("chrome-extension://%s/manifest.json" % self.extension)
        self.assertEqual(page.eval("chrome.runtime.sendMessage('ping')"),
                         {"answer": "ping", "from": "chrome-extension://%s/manifest.json" % self.extension})

    def test_screenshot_of_the_extension_page_is_written(self):
        page = self.chrome.open("chrome-extension://%s/manifest.json" % self.extension, 640, 480)
        path = page.screenshot(os.path.join(self.folder, "extension.png"))
        with open(path, "rb") as f:
            head = f.read(24)
        self.assertEqual(head[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(struct.unpack(">II", head[16:24]), (640, 480))

    def test_https_page_on_site_a_loads_with_no_certificate_error(self):
        page = self.chrome.open()
        page.send("Network.enable")
        since = len(self.chrome.events)
        page.navigate(self.sites.url("site-a.test"))
        response = self.chrome.wait_event("Network.responseReceived", page.session, since,
                                          where=lambda p: p["type"] == "Document")["response"]
        self.assertEqual(response["securityState"], "secure")
        self.assertEqual(response["securityDetails"]["subjectName"], "site-a.test")
        self.assertEqual(response["securityDetails"]["sanList"], list(driver.HOSTS))
        self.assertEqual(page.eval("[location.origin, isSecureContext]"),
                         ["https://site-a.test:%d" % self.sites.port, True])

    def test_navigator_credentials_create_works_on_site_a_with_a_virtual_authenticator(self):
        page = self.chrome.open()
        page.send("WebAuthn.enable")
        authenticator = page.send("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
            "isUserVerified": True, "automaticPresenceSimulation": True}})["authenticatorId"]
        page.navigate(self.sites.url("site-a.test"))
        made = page.eval(CREATE_PASSKEY)
        self.assertEqual(made["type"], "public-key")
        self.assertEqual(made["client"]["type"], "webauthn.create")
        self.assertEqual(made["client"]["origin"], "https://site-a.test:%d" % self.sites.port)
        stored = page.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]
        self.assertEqual([(c["rpId"], c["isResidentCredential"]) for c in stored], [("site-a.test", True)])

    def test_site_b_frame_in_a_site_a_page_has_the_other_origin(self):
        page = self.chrome.open(self.sites.url("site-a.test"))
        other = "https://site-b.test:%d" % self.sites.port
        posted = page.eval("""new Promise((resolve) => {
          const look = () => frameMessages.length ? resolve(frameMessages) : setTimeout(look, 20);
          look();
        })""", timeout=10)
        self.assertEqual(posted, [{"origin": other, "data": other}])  # event.origin is the browser's word
        self.assertTrue(page.eval("document.getElementById('other').contentDocument === null"))
        frames = [t["url"] for t in self.chrome.send("Target.getTargets")["targetInfos"] if t["type"] == "iframe"]
        self.assertIn(other + "/frame.html", frames)

    def test_sub_site_a_reaches_the_demo_server(self):
        page = self.chrome.open(self.sites.url("sub.site-a.test"))
        self.assertEqual(page.eval("[location.origin, document.title]"),
                         ["https://sub.site-a.test:%d" % self.sites.port, "sub.site-a.test"])

    def test_no_name_but_the_three_test_names_resolves(self):
        # Both are loopback, so even with the rule broken no request leaves this Mac.
        drop_kept(self, self.chrome)  # round 4: the connect files of these failures on purpose
        page = self.chrome.open()
        for url in ("https://localhost:%d/" % self.sites.port, "https://127.0.0.1:%d/" % self.sites.port):
            with self.assertRaisesRegex(driver.DriverError, "ERR_NAME_NOT_RESOLVED"):
                page.navigate(url)

    def test_no_ip_address_resolves_either(self):
        # Round 3 (C2-03): the sandbox's "localhost" is every address of this Mac, 0.0.0.0, :: and fe80::1 on any
        # interface; "MAP * ~NOTFOUND" keeps the browser off all of them, IP addresses too. Never the demo server's
        # port: with the rule broken the sandbox refuses the connection, so no request can leave this Mac.
        drop_kept(self, self.chrome)  # round 4: the connect files of these failures on purpose
        page, port = self.chrome.open(), 8443 if self.sites.port != 8443 else 8444
        own = [a for a in own_addresses() if "." in a and not a.startswith("127.")]  # the Mac's own LAN addresses
        for host in ["[::1]", "0.0.0.0", "[::]", "[fe80::1]", "192.0.2.1"] + own:
            with self.assertRaisesRegex(driver.DriverError, "ERR_NAME_NOT_RESOLVED", msg=host):
                page.navigate("https://%s:%d/" % (host, port))

    def test_chrome_has_sockets_only_to_127_0_0_1(self):
        self.chrome.open(self.sites.url("site-a.test"))  # keep-alive connections stay open
        pids = ",".join(map(str, self.chrome.pids()))
        lines = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-i", "-p", pids], capture_output=True,
                               text=True).stdout.splitlines()[1:]
        names = [line.split()[8] for line in lines]
        self.assertTrue(names, "lsof saw no socket")
        for name in names:
            for address in name.split("->"):
                self.assertTrue(address.startswith("127.0.0.1:"), name)

    def test_pids_cover_every_process_of_the_run_even_the_crash_handler_under_launchd(self):
        rows = subprocess.run(["/bin/ps", "-axww", "-o", "pid=,command="], check=True, capture_output=True,
                              text=True).stdout.splitlines()
        ours = {int(row.split(None, 1)[0]) for row in rows if self.chrome.folder in row}
        found = self.chrome.pids()
        self.assertGreater(len(ours), 1)
        self.assertEqual([p for p in ours - set(found) if driver._alive(p)], [])  # one that exited meanwhile is gone

    def test_pids_leave_out_a_program_that_shares_the_test_home_but_not_the_profile(self):
        # E7-S7c starts Larsal with Chrome's test HOME; a sibling run's HOME or another browser's profile
        # may start with this profile's text.
        profile = self.chrome.profile[len("/private"):]
        paths = (os.path.join(self.chrome.home, "Library/Application Support/Larsal/settings.json"),
                 self.chrome.home + "2/" + driver.PROFILE + "/Crashpad", self.chrome.profile + " Beta/Crashpad",
                 profile + "/Crashpad")
        waiting = [subprocess.Popen(["/bin/sh", "-c", "read line", "sh", path], stdin=subprocess.PIPE)
                   for path in paths]
        try:
            found = self.chrome.pids()
        finally:
            for process in waiting:
                process.stdin.close()
                process.wait(10)
        self.assertEqual([p.pid in found for p in waiting], [False, False, False, True])  # True: as the crash handler

    def test_pids_cover_the_test_browsers_crash_handler_by_its_database_in_the_test_home(self):
        # Chromium keeps its crash database in the HOME under its own name, not in the profile; its two crash
        # handlers run under launchd. The /tmp form, as Chromium gives it; a sibling HOME is not ours.
        crashpad = "/Library/Application Support/Chromium/Crashpad"
        home = self.chrome.home[len("/private"):]
        paths = ("--database=" + home + crashpad, "--database=" + home + "2" + crashpad)
        waiting = [subprocess.Popen(["/bin/sh", "-c", "read line", "sh", path, "--annotation=x"], stdin=subprocess.PIPE)
                   for path in paths]
        try:
            found = self.chrome.pids()
        finally:
            for process in waiting:
                process.stdin.close()
                process.wait(10)
        self.assertEqual([p.pid in found for p in waiting], [True, False])

    def test_echo_host_answers_connect_native_from_the_int_01_8_folder(self):
        manifest = driver.install_echo_host(self.chrome.home, self.extension)
        self.assertEqual(manifest, os.path.join(
            self.chrome.home, "Library/Application Support/Google/Chrome/NativeMessagingHosts/app.larsal.test.echo.json"))
        answer = self.chrome.worker(self.extension).eval(CONNECT_ECHO)
        self.assertEqual(answer, {"echo": {"hello": "echo"}, "caller": ["chrome-extension://%s/" % self.extension]})

    def test_the_browsers_bundle_id_is_watched_in_controlcenters_log(self):
        # Round 2, F1: ControlCenter names a status item by its app's bundle id ("bid:org.chromium.Chromium-...").
        bundle = driver.bundle_id(self.chrome.binary)
        self.assertRegex(bundle or "", r"^(org\.chromium\.Chromium|com\.google\.Chrome)$")
        self.assertIn(bundle, driver.BUNDLES)

    def test_live_main_chrome_runs_with_the_mock_keychain_flag(self):
        self.assertIn("--use-mock-keychain", driver.command_line(self.chrome.pid).split())
        self.assertIn(self.chrome.pid, driver.RUN_PIDS)  # the after-run keychain log check looks for it

    def test_no_window_no_dock_icon_and_focus_never_moves_so_far(self):
        self.assertEqual(self.chrome.hits, [])
        self.assertIsNone(self.chrome.guard.poll(), "the window guard must still run")
        apps = subprocess.run(["/usr/bin/lsappinfo", "list"], capture_output=True, text=True).stdout
        self.assertIn('pid = %d type="BackgroundOnly"' % self.chrome.pid, apps)  # no Dock icon, no menu bar

    def test_every_process_of_the_run_is_inside_the_drivers_sandbox(self):
        # LD-285: the browser and every helper. sandbox-exec execs the browser, so the main PID is the browser's.
        self.assertTrue(driver.command_line(self.chrome.pid).startswith(self.chrome.binary + " "))
        pids = self.chrome.pids()
        self.assertGreater(len(pids), 1)
        free = [p for p in pids if driver._alive(p) and not driver.denies_lookup(p, "com.apple.cfprefsd.agent")]
        self.assertEqual(free, [])


class RunSafetyTests(unittest.TestCase):
    """A whole run, start to close."""

    def test_close_stops_chrome_by_pid_with_no_window_no_focus_change_and_owner_files_untouched(self):
        before = driver.owner_times()
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        self.assertIn(chrome.pid, driver.RUN_PIDS)  # recorded at start, before any pids() call
        chrome.open("about:blank")
        # Chrome's singleton socket: under the run's folder, not the owner's temp folder (it ignores TMPDIR).
        self.assertTrue(os.readlink(os.path.join(chrome.profile, "SingletonSocket")).startswith(chrome.folder + "/"))
        pids = chrome.pids()
        self.assertGreater(len(pids), 1)
        chrome.close()  # raises on a guard hit, a helper left running or a changed owner file
        self.assertEqual([p for p in pids if driver._alive(p)], [])
        self.assertEqual(chrome.hits, [])
        self.assertIsNotNone(chrome.front_before)
        # Round 4 (C2R3-10): the owner may switch between their own apps meanwhile; no process of the run is ever
        # the frontmost app.
        self.assertEqual({chrome.front_before, chrome.front_after} & chrome.seen, set())
        self.assertEqual(driver.owner_times(), before)
        self.assertLessEqual(set(pids) | {chrome.guard.pid}, driver.RUN_PIDS)

    def test_a_chrome_whose_command_line_lacks_the_mock_keychain_flag_is_stopped(self):
        # Chrome itself always gets the flag; only the reading of its command line is faked.
        before, made = set(driver.RUN_PIDS), []
        self.addCleanup(lambda: [chrome.close() for chrome in made])  # only when the driver lets Chrome run
        with mock.patch.object(driver, "command_line", lambda pid: "/x/Chromium --headless=new"):
            with self.assertRaisesRegex(driver.DriverError, "--use-mock-keychain is not on Chrome's command line") as e:
                made.append(driver.Chrome())
        drop_kept_in(self, e.exception)  # round 4: this failure on purpose keeps its connects too
        ran = driver.RUN_PIDS - before
        self.assertTrue(ran)
        self.assertEqual([p for p in ran if driver._alive(p)], [])

    def test_a_guard_hit_fails_the_run(self):
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        chrome.hits.append("window 99999")  # as the guard reports a window
        with self.assertRaisesRegex(driver.DriverError, "rule 10"):
            chrome.close()

    def test_a_guard_hit_stops_chrome_at_once_even_when_the_guard_stops_nothing(self):
        folder = temp_folder(self)
        trigger, fake = os.path.join(folder, "hit"), os.path.join(folder, "guard")
        with open(fake, "w") as f:  # reports a window when told to, and stops nothing itself
            f.write('#!/bin/sh\necho ready 0 false\nwhile [ ! -e "%s" ]; do sleep 0.05; done\n'
                    'echo window 99999\nread line\necho done 0 1\n' % trigger)
        os.chmod(fake, 0o700)
        with mock.patch.object(driver, "guard_binary", lambda: fake):
            chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        open(trigger, "w").close()
        self.assertTrue(chrome._exited(2), "a hit must stop Chrome at once")
        with self.assertRaisesRegex(driver.DriverError, "rule 10: window guard: window 99999"):
            chrome.close()

    def test_a_window_guard_that_stops_early_stops_chrome_and_fails_the_run(self):
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        pids = chrome.pids()
        os.kill(chrome.guard.pid, signal.SIGKILL)  # our own child
        self.assertTrue(chrome._exited(1), "Chrome must not run on with no guard")
        with self.assertRaisesRegex(driver.DriverError, "rule 10: window guard: stopped early"):
            chrome.close()
        self.assertEqual([p for p in pids if driver._alive(p)], [])

    def test_a_window_guard_that_stops_before_chrome_starts_still_stops_chrome(self):
        fake = os.path.join(temp_folder(self), "guard")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\necho ready 0 false\n")  # starts, then stops before Chrome does
        os.chmod(fake, 0o700)
        made, high = [], driver._high
        self.addCleanup(lambda: [chrome.close() for chrome in made])  # only when the driver lets Chrome run

        def late(fd):  # Chrome starts after the fake guard has stopped
            time.sleep(0.2)
            return high(fd)

        with mock.patch.object(driver, "guard_binary", lambda: fake), mock.patch.object(driver, "_high", late):
            with self.assertRaisesRegex(driver.DriverError, "window guard: stopped early") as e:
                made.append(driver.Chrome())
        drop_kept_in(self, e.exception)  # round 4: this failure on purpose keeps its connects too

    def test_a_change_of_the_frontmost_app_fails_the_run(self):
        # Round 4 (C2R3-10): a change to a process of the run fails it; the owner's own switch is only noted
        # (TestBrowserTests has both, with stand-ins).
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        pid = chrome.front_before = chrome.pid  # as if the browser had been in front at the start
        with self.assertRaisesRegex(driver.DriverError, r"rule 10: a process of the run was the frontmost app: \[%d\]"
                                    % pid):
            chrome.close()

    def test_owner_files_are_checked_even_when_another_check_fails(self):
        watched = os.path.join(temp_folder(self), "watched")
        open(watched, "w").close()
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        chrome.hits.append("window 99999")
        chrome.before[watched] = -1  # as if this watched file changed during the run
        with self.assertRaisesRegex(driver.OwnerFilesChanged, "watched.*rule 10"):
            chrome.close()

    def test_a_guard_that_does_not_start_fails_the_run_and_leaves_no_folder(self):
        made, mkdtemp = [], tempfile.mkdtemp

        def record(**kwargs):
            made.append(mkdtemp(**kwargs))
            return made[-1]

        with mock.patch.object(driver, "guard_binary", lambda: "/usr/bin/true"), \
                mock.patch.object(driver.tempfile, "mkdtemp", record):
            with self.assertRaisesRegex(driver.DriverError, "window guard did not start"):
                driver.Chrome()
        self.assertEqual(len(made), 1)
        self.assertFalse(os.path.exists(made[0]))

    def test_launch_flags_keep_chrome_off_the_owners_keychain_profile_and_network(self):
        profile = "/private/tmp/x/home/Library/Application Support/Google/Chrome"
        self.assertEqual(driver.chrome_flags(profile, "SPKI"), [
            "--headless=new", "--remote-debugging-pipe", "--enable-unsafe-extension-debugging",
            "--user-data-dir=" + profile, "--use-mock-keychain", "--no-sandbox", "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
            "--disable-updater-scheduler", "--disable-features=MacAppCodeSignClone,OmniboxEverywhere", "--disable-sync",
            "--disable-default-apps", "--disable-breakpad", "--metrics-recording-only", "--no-proxy-server",
            "--host-resolver-rules=MAP site-a.test 127.0.0.1, MAP site-b.test 127.0.0.1, "
            "MAP sub.site-a.test 127.0.0.1, MAP * ~NOTFOUND",
            "--ignore-certificate-errors-spki-list=SPKI",
        ])
        self.assertNotIn("--ignore-certificate-errors-spki-list=SPKI", driver.chrome_flags(profile))

    def test_an_updater_in_the_test_home_fails_the_run(self):
        # F-149: in a HOME with no updater, Chrome's updater installs itself there and runs launchctl in the
        # owner's session; --disable-updater-scheduler stops it, and this tripwire sees one that ran anyway.
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        for part in ("Library/LaunchAgents", "Library/Application Support/Google/GoogleUpdater"):
            os.makedirs(os.path.join(chrome.home, part))  # as the updater leaves them
        with self.assertRaisesRegex(driver.DriverError, "updater ran in the test HOME.*LaunchAgents, .*GoogleUpdater"):
            chrome.close()

    def test_a_dns_error_page_asks_no_dns_server(self):
        # F-150: the error page's DNS probe has its own resolver, which --host-resolver-rules does not cover.
        # The NetLog sees even a socket that lives a millisecond; one lsof snapshot cannot.
        # Round 3 (C2-01): the browser writes only in the run's own folders, so the NetLog is in the run root,
        # beside the test HOME.
        root = temp_folder(self)
        log = os.path.join(root, "net.json")
        chrome = driver.Chrome(home=os.path.join(root, "home"),
                               args=["--log-net-log=" + log, "--net-log-capture-mode=Everything"])
        self.addCleanup(chrome.close)
        drop_kept(self, chrome)  # round 4: the connect file of this failure on purpose
        with self.assertRaisesRegex(driver.DriverError, "ERR_NAME_NOT_RESOLVED"):
            chrome.open().navigate("https://localhost/")
        time.sleep(1)  # the probe starts about 20 ms after the error
        chrome.close()
        with open(log) as f:
            net = json.load(f)
        names = {number: name for name, number in net["constants"]["logEventTypes"].items()}
        seen = [names[event["type"]] for event in net["events"]]
        self.assertIn("URL_REQUEST_START_JOB", seen, "the NetLog holds the navigation")
        dns = [name for name in seen if name.startswith("DNS_TRANSACTION")]
        self.assertEqual(len(dns), 0, dns[:5])  # a count: the whole list makes a huge message

    def test_flags_the_driver_sets_cannot_be_overridden(self):
        # Each value is safe even if the check were gone; the check refuses the name.
        other = os.path.join(temp_folder(self), "profile")
        for flag in ("--user-data-dir=" + other, "-user-data-dir=" + other, "--host-resolver-rules=MAP * ~NOTFOUND",
                     "-host-resolver-rules=MAP * ~NOTFOUND", "--headless=new"):
            with self.assertRaisesRegex(driver.DriverError, "driver's own"):
                driver.Chrome(args=[flag]).close()


class GuardTests(unittest.TestCase):
    """The owner-safety checks themselves, without Chrome."""

    def test_window_guard_reports_windows_and_focus_under_its_root(self):
        # Root 1 (launchd) is above every process, so the owner's own windows count; --dry-run stops nothing.
        lines = []
        with subprocess.Popen([driver.guard_binary(), "1", "--dry-run"], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True) as guard:
            for line in guard.stdout:
                lines.append(line.split()[0])
                if lines[-1] == "ready":
                    break
            guard.stdin.close()
            lines += [line.split()[0] for line in guard.stdout]
        self.assertIn("window", lines)
        self.assertIn("front", lines)
        self.assertEqual(lines[-1], "done")

    def test_the_guard_compiles_with_its_module_caches_in_its_own_folder(self):
        # swiftc's module caches go into the guard's own run folder, whatever the caller's environment says.
        # Round 3 (C1R2-02, C2-07): xcrun's own lookup cache too, which it keeps in the owner's T/xcrun_db
        # whatever TMPDIR says, unless the xcrun_db variable names another file.
        # Round 4 (C2R3-01, C1R3-02): no xcrun at all: the toolchain's swiftc by its full path, SDKROOT the SDK's
        # real path, inside the driver's sandbox for the guard's own folder, no DEVELOPER_DIR, and the folder as
        # LARSAL_TEST_INSTANCE_DIR (C2R3-02).
        calls = []
        owner = {"CLANG_MODULE_CACHE_PATH": "/owner/clang", "SWIFT_MODULECACHE_PATH": "/owner/swift",
                 "TMPDIR": "/owner/tmp", "xcrun_db": "/owner/T/xcrun_db", "DEVELOPER_DIR": driver.XCODE,
                 "SDKROOT": "/owner/sdk", "LARSAL_TEST_INSTANCE_DIR": "/owner/T"}
        with mock.patch.object(driver, "_guard", []), mock.patch.dict(os.environ, owner), \
                mock.patch.object(driver.subprocess, "run", lambda argv, **k: calls.append((argv, k["env"]))):
            folder = os.path.dirname(driver.guard_binary())
        self.addCleanup(shutil.rmtree, folder, True)
        (argv, env), = calls
        self.assertEqual(driver.SWIFTC, "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain"
                                        "/usr/bin/swiftc")
        self.assertEqual(argv, [driver.SANDBOX, "-p", driver.sandbox_profile((folder,)), driver.SWIFTC, "-O", "-o",
                                os.path.join(folder, "window_guard"), os.path.join(driver.HERE, "window_guard.swift")])
        self.assertEqual([a for a in argv if "xcrun" in a or "xcodebuild" in a], [])
        self.assertTrue(folder.startswith("/tmp/larsal-guard-"), folder)
        self.assertEqual((env["CLANG_MODULE_CACHE_PATH"], env["SWIFT_MODULECACHE_PATH"], env["TMPDIR"],
                          env["xcrun_db"], env["SDKROOT"], env["LARSAL_TEST_INSTANCE_DIR"]),
                         (os.path.join(folder, "clang"), os.path.join(folder, "swift"), folder,
                          os.path.join(folder, "xcrun_db"), os.path.realpath(driver.SDK), folder))
        self.assertNotIn("DEVELOPER_DIR", env)

    def test_a_cold_guard_compile_runs_no_xcrun_and_leaves_the_owners_developer_caches_alone(self):
        # Round 4 (C2R3-01, C1R3-02): a real compile into a new folder. libxcrun keeps its lookup cache in the
        # owner's T/xcrun_db and xcodebuild its plug-in cache in the owner's C/com.apple.DeveloperTools: neither
        # runs, so the tripwire (the compile's xcrun_db, a file in the guard's folder only an xcrun would make) is
        # never made and both owner caches keep every inode, size and modification time.
        per_user = os.path.realpath(driver.USER_FOLDERS)
        caches = (os.path.join(per_user, "T", "xcrun_db"), os.path.join(per_user, "C", "com.apple.DeveloperTools"))
        before = [lstat_tree(top) for top in caches]
        with mock.patch.object(driver, "_guard", []):
            binary = driver.guard_binary()
        folder = os.path.dirname(binary)
        self.addCleanup(shutil.rmtree, folder, True)
        self.assertFalse(os.path.lexists(os.path.join(folder, "xcrun_db")), "an xcrun ran for the compile")
        self.assertEqual([lstat_tree(top) for top in caches], before)
        with subprocess.Popen([binary, str(os.getpid()), "--dry-run"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True) as guard:
            ready = guard.stdout.readline()
            guard.stdin.close()
            guard.stdout.read()
        self.assertTrue(ready.startswith("ready "), ready)

    def test_window_guard_keeps_looking_and_is_quiet_for_a_root_with_no_window(self):
        # The shell keeps itself as the guard's parent ("; :" after it), so the guard is two levels under ROOT.
        command = "'%s' %d --dry-run; :" % (driver.guard_binary(), os.getpid())
        with subprocess.Popen(["/bin/sh", "-c", command], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True) as guard:
            ready = guard.stdout.readline().split()
            time.sleep(0.3)
            guard.stdin.close()
            rest = [line.split() for line in guard.stdout]
        self.assertEqual(ready[0], "ready")
        self.assertEqual(ready[2], "true", "the guard counts a process two levels under ROOT")
        self.assertEqual([line[0] for line in rest], ["done"])
        self.assertGreaterEqual(int(rest[0][2]), 3, "the guard looks again every 50 ms, not once")

    def test_window_guard_refuses_to_stop_anything_for_a_root_above_every_process(self):
        # Root 0 only: with the refusal gone no real process is under 0, and the guard never stops a PID <= 1.
        with subprocess.Popen([driver.guard_binary(), "0"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True) as guard:
            first = guard.stdout.readline()
            guard.stdin.close()
            guard.wait(10)
        self.assertTrue(first.startswith("refused"), first)
        self.assertEqual(guard.returncode, 2)

    def test_owner_times_check_fails_when_a_watched_file_changes(self):
        for part in ("Preferences/com.google.Chrome.plist", "Application Support/Google/Chrome"):
            self.assertIn(os.path.join(driver.REAL_HOME, "Library", part), driver.OWNER_PATHS)
        # F-147: Chrome's code-signing clone of its app, in the owner's temp folder, is watched too.
        clone = os.path.join(os.path.dirname(os.confstr(65537).rstrip("/")), "X", "com.google.Chrome.code_sign_clone")
        self.assertIn(clone, driver.OWNER_PATHS)
        # LD-276: macOS's own services change this file's time about every 10 minutes; it is checked by process.
        self.assertNotIn(os.path.join(driver.REAL_HOME, "Library/Keychains/login.keychain-db"), driver.OWNER_PATHS)
        path = os.path.join(temp_folder(self), "watched")
        open(path, "w").close()
        before = driver.owner_times((path,))
        driver.check_owner_times(before)
        os.utime(path, ns=(0, 0))
        with self.assertRaises(driver.OwnerFilesChanged):
            driver.check_owner_times(before)
        missing = driver.owner_times((path + ".new",))
        open(path + ".new", "w").close()
        with self.assertRaises(driver.OwnerFilesChanged):
            driver.check_owner_times(missing)

    def test_keychain_commits_are_only_the_writes_of_a_pid_of_the_run(self):
        keychain = "/Users/demo/Library/Keychains/login.keychain-db"
        log = "\n".join([
            "Timestamp               Ty Process[PID:TID]",
            "2026-10-31 21:13:16.982 Df networkserviceproxy[56949:f59156] [com.apple.securityd:atomicfile] "
            "0x8f0972900 commited %s.sb-7d634cae-hjDl06 to %s" % (keychain, keychain),  # macOS, not ours
            "2026-10-31 21:13:17.001 Df Google Chrome[4242:1a2b] [com.apple.securityd:atomicfile] "
            "0x8f0972901 commited %s.sb-7d634cae-AbCd12 to %s" % (keychain, keychain),  # ours, a name with a space
            "2026-10-31 21:13:17.002 Df Google Chrome[4242:1a2c] [com.apple.securityd:keychain] opened %s" % keychain,
        ])
        self.assertEqual(driver.keychain_commits(log, {4242}), [log.splitlines()[2]])
        self.assertEqual(driver.keychain_commits(log, {56949}), [log.splitlines()[1]])
        self.assertEqual(driver.keychain_commits(log, {4243, 56950}), [])

    def test_a_keychain_write_by_this_run_stops_the_suite_run(self):
        line = ("2026-10-31 21:13:17.001 Df Python[%d:1a2b] [com.apple.securityd:atomicfile] 0x1 commited "
                "/tmp/x/login.keychain-db.sb-1 to /tmp/x/login.keychain-db" % os.getpid())
        windows = []
        with mock.patch.object(driver, "keychain_log", lambda start, end: windows.append((start, end)) or line):
            with self.assertRaisesRegex(driver.OwnerFilesChanged, r"STOP \(LD-276\)"):
                tearDownModule()
        self.assertEqual(windows[0][0], RUN["start"])  # the window opens when the suite run starts

    def test_check_keychain_log_stops_on_a_write_by_a_pid_of_the_run_only(self):
        # LD-278 (3): the one helper every suite calls after its run (test_extension.py too).
        line = ("2026-11-08 06:00:00.001 Df larsal-bridge[%d:1a2b] [com.apple.securityd:atomicfile] 0x1 commited "
                "/tmp/x/login.keychain-db.sb-1 to /tmp/x/login.keychain-db")
        other = max(driver.RUN_PIDS | {os.getpid()}) + 100000  # no PID of this run
        windows = []
        log = lambda pid: lambda start, end: windows.append((start, end)) or line % pid
        with mock.patch.object(driver, "keychain_log", log(other)):
            driver.check_keychain_log(1793479500.0)  # macOS's own write: no stop
        with mock.patch.object(driver, "RUN_PIDS", driver.RUN_PIDS | {other}):
            with mock.patch.object(driver, "keychain_log", log(other)):
                with self.assertRaisesRegex(driver.OwnerFilesChanged, r"STOP \(LD-276\).*larsal-bridge"):
                    driver.check_keychain_log(1793479500.0)  # a PID the run added (Larsal, larsal-bridge)
        with mock.patch.object(driver, "keychain_log", log(os.getpid())):
            with self.assertRaises(driver.OwnerFilesChanged):
                driver.check_keychain_log(1793479500.0)  # the test process itself
        self.assertEqual([w[0] for w in windows], [1793479500.0] * 3)
        self.assertTrue(all(time.time() - 60 < w[1] <= time.time() for w in windows))  # up to now

    def test_keychain_log_reads_securityd_for_the_whole_window_and_fails_when_log_fails(self):
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, 0, "x")

        with mock.patch.object(driver.subprocess, "run", run):
            self.assertEqual(driver.keychain_log(1793479500.9, 1793479530.2), "x")
        stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
        self.assertEqual(calls, [(["/usr/bin/log", "show", "--start", stamp(1793479500), "--end", stamp(1793479531),
                                   "--predicate", 'subsystem == "com.apple.securityd" AND '
                                   'eventMessage CONTAINS "login.keychain-db"', "--style", "compact"],
                                  {"check": True, "capture_output": True, "text": True})])

    def test_test_home_outside_tmp_is_refused(self):
        folder = temp_folder(self)
        link = os.path.join(folder, "link-to-home")
        os.symlink(driver.REAL_HOME, link)
        for path in (driver.REAL_HOME, "/tmp", "/private/tmp/", "/var/tmp/x", link):
            with self.assertRaises(driver.DriverError, msg=path):
                driver.check_test_home(path)
        self.assertEqual(driver.check_test_home(folder), os.path.realpath(folder))
        with self.assertRaises(driver.DriverError):  # /var/empty is not writable: no write even if the check broke
            driver.install_echo_host("/var/empty", "a" * 32)

    def test_a_link_in_a_test_home_cannot_send_chrome_or_the_echo_host_outside_it(self):
        # F-151: check_test_home resolves only the HOME's own path. A link under it could lead to the owner's
        # Library; here the stand-in is a folder under /tmp, so nothing real is at risk.
        folder = temp_folder(self)
        outside = os.path.join(folder, "outside")
        os.makedirs(outside)
        target = os.path.join(outside, "file")
        open(target, "w").close()
        homes = {}
        for name, part, to in (("library", "Library", outside), ("default", driver.PROFILE + "/Default", outside),
                               ("program", "echo.py", target),
                               ("manifest", driver.NATIVE_HOSTS + "/app.larsal.test.echo.json", target)):
            homes[name] = os.path.join(folder, name)
            link = os.path.join(homes[name], part)
            os.makedirs(os.path.dirname(link))
            os.symlink(to, link)
        made = []
        self.addCleanup(lambda: [chrome.close() for chrome in made])  # only when the driver lets Chrome run
        for name in ("library", "default"):
            with self.assertRaisesRegex(driver.DriverError, "goes through a link", msg=name):
                made.append(driver.Chrome(home=homes[name]))
        for name in ("library", "program", "manifest"):
            with self.assertRaisesRegex(driver.DriverError, "goes through a link", msg=name):
                driver.install_echo_host(homes[name], "a" * 32)
        self.assertEqual(os.listdir(outside), ["file"])  # nothing written at the link target
        self.assertEqual(os.path.getsize(target), 0)

    def test_the_owners_chromium_files_and_its_code_sign_clone_are_watched_too(self):
        # The test browser's own names for what Chrome keeps under com.google.Chrome; its first guarded run
        # wrote the Preferences plist (through cfprefsd, outside any sandbox of ours).
        for part in ("Preferences/org.chromium.Chromium.plist", "Application Support/Chromium",
                     "Application Support/Chromium/Default", "Caches/Chromium"):
            self.assertIn(os.path.join(driver.REAL_HOME, "Library", part), driver.OWNER_PATHS)
        clone = os.path.join(os.path.dirname(os.confstr(65537).rstrip("/")), "X", "org.chromium.Chromium.code_sign_clone")
        self.assertIn(clone, driver.OWNER_PATHS)

    def test_the_browser_is_the_test_chrome_variable_else_todays_chrome(self):
        # Round 3 (C2-12): there is no "else" any more; the name stays (tests are added, never renamed).
        with self.assertRaisesRegex(driver.DriverError, "LARSAL_TEST_CHROME is not set"):
            driver.browser_binary({})
        binary = fake_browser(self)
        link = os.path.join(temp_folder(self), "browser")
        os.symlink(binary, link)
        for path in (binary, link):
            self.assertEqual(driver.browser_binary({driver.TEST_CHROME: path}), os.path.realpath(binary))

    def test_a_browser_under_applications_that_is_not_todays_chrome_is_refused(self):
        # The owner's own browsers stay untouched; a link cannot lead there either. Round 3 (C2-12): nothing under
        # /Applications is started at all, Chrome included.
        other = "/Applications/Other.app/Contents/MacOS/Other"
        link = os.path.join(temp_folder(self), "browser")
        os.symlink(other, link)
        for path in (other, link, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"):
            with self.assertRaisesRegex(driver.DriverError, "is not under .*, where the pinned test browser is"):
                driver.browser_binary({driver.TEST_CHROME: path})
        with self.assertRaisesRegex(driver.DriverError, "must be an absolute path"):
            driver.browser_binary({driver.TEST_CHROME: "browser"})

    def test_a_browser_its_manifest_does_not_name_with_its_sha256_is_refused(self):
        binary = fake_browser(self)
        manifest = os.path.join(os.path.dirname(os.path.dirname(binary)), driver.MANIFEST)
        with open(manifest) as f:
            good = json.load(f)
        folder = os.path.dirname(manifest)
        for name, recorded in (("another hash", dict(good["binary"], sha256="0" * 64)),
                               ("another path", dict(good["binary"], path="app/other"))):
            with open(manifest, "w") as f:
                json.dump({"binary": recorded}, f)
            pin(self, folder)  # round 3: as if this were the pinned manifest, so the binary check is what refuses
            with self.assertRaisesRegex(driver.DriverError, "is not the binary", msg=name):
                driver.browser_binary({driver.TEST_CHROME: binary})
        with open(manifest, "w") as f:
            f.write("{")
        pin(self, folder)
        with self.assertRaisesRegex(driver.DriverError, "no MANIFEST.json above it names it"):
            driver.browser_binary({driver.TEST_CHROME: binary})
        os.remove(manifest)
        with self.assertRaisesRegex(driver.DriverError, "no MANIFEST.json above it names it"):
            driver.browser_binary({driver.TEST_CHROME: binary})
        with open(manifest, "w") as f:
            json.dump(good, f)
        pin(self, folder)
        self.assertEqual(driver.browser_binary({driver.TEST_CHROME: binary}), os.path.realpath(binary))

    def test_the_sandbox_lets_out_only_loopback_and_no_write_under_its_walls(self):
        # LD-285. With no sandbox the same probe fails otherwise (no route on lo0), reaches the resolver's
        # socket and writes: the EPERMs are the sandbox's.
        # Round 2 (F6): no bind on any IP address inside, not on every interface, not even on loopback.
        # Round 3 (C2-01, C2-03): the profile allows writes only in the run's own folders (here another one, not
        # `wall`) and the loopback connection only on the port it names (here the listener's).
        wall = temp_folder(self)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        self.addCleanup(listener.close)
        port = listener.getsockname()[1]
        argv = [sys.executable, "-I", "-c", NET_PROBE, wall, str(port)]
        self.assertEqual(probe(driver.sandboxed(argv, driver.sandbox_profile((temp_folder(self),), (port,)))),
                         {"tcp": "EPERM", "udp": "EPERM", "resolver": "EPERM", "loopback": "connected",
                          "bind-any": "EPERM", "listen-loopback": "EPERM", "wall": "EPERM"})
        free = probe(argv)
        self.assertEqual((free["resolver"], free["loopback"], free["bind-any"], free["listen-loopback"], free["wall"]),
                         ("connected", "connected", "bound", "bound", "written"))
        self.assertNotEqual(free["tcp"], "EPERM")
        self.assertIn('(deny file-write*)\n(allow file-write* (subpath "/private/tmp/a") (subpath "/private/tmp/b"))\n'
                      '(allow file-write* (literal "/dev/null"))\n', driver.sandbox_profile(("/tmp/b", "/tmp/a")))
        with self.assertRaises(driver.DriverError):
            driver.sandbox_profile(('/tmp/a") (allow file-write* (subpath "/',))
        with self.assertRaises(driver.DriverError):
            driver.sandbox_profile(ports=('1")) (allow network* (remote ip "*:*',))

    def test_the_sandbox_denies_the_services_that_would_write_or_ask_for_the_owner(self):
        # Seen in the test browser's first guarded run: cfprefsd wrote the owner's Preferences, lsd registered
        # the app with LaunchServices. The others ask on the owner's screen or reach the owner's clipboard and apps.
        denied = ["com.apple.cfprefsd.agent", "com.apple.lsd.modifydb", "com.apple.lsd.mapdb", "com.apple.tccd",
                  "com.apple.pasteboard.1", "com.apple.coreservices.appleevents", "com.apple.CoreAuthentication.daemon"]
        kept = ["com.apple.coreservices.launchservicesd", "com.apple.cfprefsd.daemon"]  # no check-in: no start
        argv = [sys.executable, "-I", "-c", LOOKUP_PROBE] + denied + kept
        self.assertEqual(probe(argv), dict.fromkeys(denied + kept, 0))  # each one is there
        inside = probe(driver.sandboxed(argv))
        self.assertEqual([name for name in denied if inside[name] == 0], [])
        self.assertEqual([inside[name] for name in kept], [0, 0])

    def test_the_keychain_log_is_not_read_when_the_clock_was_changed_during_the_run(self):
        # 2026-11-12: System Settings set the clock back a day for 20 s during a run; the log's lines of those
        # seconds carried the day before, outside the window keychain_log reads.
        calls = []
        with mock.patch.object(driver, "keychain_log", lambda start, end: calls.append(start) or ""):
            driver.check_keychain_log(time.time() - 1)  # a steady clock: the log is read
            for name, value in (("CLOCK", driver.CLOCK - 86400), ("CLOCK_STEPS", [time.time()])):
                with mock.patch.object(driver, name, value):  # set back since the start; back and forth again
                    with self.assertRaisesRegex(driver.DriverError, "clock was changed during the run", msg=name):
                        driver.check_keychain_log(time.time() - 1)
        self.assertEqual(len(calls), 1)

    # Round 2 (2026-11-12): the Checker's F1 to F6 and the lead's rulings.

    def test_the_sandbox_denies_each_service_by_name(self):
        # F3: one name for each entry of SERVICES, asked of a live process inside the sandbox (sandbox_check asks
        # the sandbox only: nothing is looked up). F1, F2: the menu bar's status items and location registration;
        # round 2: Handoff (useractivityd) and notifications (usernoted).
        # Round 3 (C2-02, C2-08): notifications' other names, their alerts and banners, the passkey and credential
        # sheets, and macOS's own web browser's launch agent.
        denied = ["com.apple.cfprefsd.agent", "com.apple.lsd.modifydb", "com.apple.tccd.system", "com.apple.pboard",
                  "com.apple.pasteboard.1", "com.apple.coreservices.appleevents", "com.apple.SecurityAgent",
                  "com.apple.CoreAuthentication.daemon", "com.apple.LocalAuthentication.UIAgent",
                  "com.apple.biometrickitd", "com.openssh.ssh-agent", "com.apple.controlcenter.statusitems",
                  "com.apple.locationd.desktop.registration", "com.apple.CoreLocation.agent",
                  "com.apple.coreservices.lsuseractivitymanager.xpc", "com.apple.usernoted.client",
                  "com.apple.usernotifications.usernotificationservice", "com.apple.UNCUserNotification",
                  "com.apple.notificationcenterui.main", "com.apple.SystemBanner",
                  "com.apple.AuthenticationServicesCore.AuthenticationServicesAgent", "com.apple.SafariLaunchAgent",
                  # Round 4 (C2R3-03, C2R3-04): each live name the browser asked or a password prompt would use,
                  # denied one at a time, each with a single start, then the suites.
                  "com.apple.spotlight.IndexAgent", "com.apple.linkd.autoShortcut",
                  "com.apple.synapse.backlink-service", "com.apple.dock.fullscreen",
                  "com.apple.distributed_notifications@Uv3", "com.apple.ctkd.token-client", "com.apple.authd",
                  "com.apple.security.agent", "com.apple.security.agent.login", "com.apple.security.authhost",
                  "com.apple.SecurityServer", "com.apple.securityd.xpc"]
        # More names of the same entries, as launchd lists them: usernoted's and usernotificationsd's, the banner
        # service, the alerts, and the agent's other names.
        also = ["com.apple.usernotifications.remotenotificationservice", "com.apple.usernotifications.listener",
                "com.apple.usernotifications.alert-coordination", "com.apple.usernotificationsvendor.listener",
                "com.apple.SystemBannerService", "com.apple.notificationcenterui.customalerts",
                "com.apple.AuthenticationServices.AutoFill",
                "com.apple.AuthenticationServicesCore.AuthenticationServicesAgent.CredentialExchange"]
        kept = ["com.apple.coreservices.launchservicesd", "com.apple.cfprefsd.daemon"]  # no check-in: no start
        self.assertEqual(len(re.findall(r"\(global-name", driver.SERVICES)), len(denied))  # a name for each entry
        sleeper = sandboxed_sleep(self)
        # Round 4 (C2R3-07): every question is asked with SANDBOX_CHECK_NO_REPORT, so this test leaves no kernel
        # deny row for its sleeper (the watch around the suite reads them).
        types_asked, check = [], driver._SANDBOX_CHECK
        with mock.patch.object(driver, "_SANDBOX_CHECK", lambda *a: types_asked.append(a[2]) or check(*a)):
            self.assertEqual([name for name in denied + also if not driver.denies_lookup(sleeper.pid, name)], [])
            self.assertEqual([name for name in kept if driver.denies_lookup(sleeper.pid, name)], [])
        self.assertEqual(set(types_asked), {2 | 0x40000000})

    def test_denies_lookup_asks_for_a_global_name_with_no_report(self):
        # C2R3-07: SANDBOX_CHECK_NO_REPORT (0x40000000) with the global-name filter (2): sandbox_check only asks,
        # and the kernel logs no deny row that a log check could take for a lookup.
        calls = []
        with mock.patch.object(driver, "_SANDBOX_CHECK", lambda *a: calls.append(a) or 1):
            self.assertTrue(driver.denies_lookup(4242, "com.apple.tccd"))
        with mock.patch.object(driver, "_SANDBOX_CHECK", lambda *a: calls.append(a) or 0):
            self.assertFalse(driver.denies_lookup(4242, "com.apple.cfprefsd.daemon"))
        self.assertEqual(calls, [(4242, b"mach-lookup", 0x40000002, b"com.apple.tccd"),
                                 (4242, b"mach-lookup", 0x40000002, b"com.apple.cfprefsd.daemon")])

    def test_a_socket_on_every_interface_is_beyond_loopback(self):
        # F6: "*:port" listens on every interface; "*:*" has no address and no port yet, and reaches nothing.
        lsof = ("p4242\nf5\nn*:5353\nf6\nn*:*\nf7\nn127.0.0.1:50000->127.0.0.1:8443\nf8\nn[::1]:50001\n"
                "f9\nn*:8080\nf10\nnlocalhost:8443\n")
        with mock.patch.object(driver.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, lsof)):
            # Round 3 (C2-03): only 127.0.0.1 and ::1 are loopback; lsof -n never prints "localhost" anyway.
            self.assertEqual(driver.outside_loopback([4242]), ["*:5353", "*:8080", "localhost:8443"])

    def test_a_changed_framework_or_helper_of_the_test_browser_is_refused_before_anything_starts(self):
        # F4: every file and link of the browser's app, not only the launcher it starts.
        binary = fake_browser(self, files={"app/Helpers/helper": "#!/bin/sh\n", "app/Versions/1/framework": "f1"},
                              links={"app/Current": "Versions/1"})
        folder, env = os.path.dirname(os.path.dirname(binary)), {driver.TEST_CHROME: binary}
        self.assertEqual(driver.browser_binary(env), os.path.realpath(binary))
        helper, framework = os.path.join(folder, "app/Helpers/helper"), os.path.join(folder, "app/Versions/1/framework")

        def write(path, text):
            with open(path, "w") as f:
                f.write(text)

        for name, change, undo, expected in (
                ("a changed helper", lambda: write(helper, "#!/bin/ex\n"), lambda: write(helper, "#!/bin/sh\n"),
                 "app/Helpers/helper"),
                ("a changed framework", lambda: write(framework, "f2"), lambda: write(framework, "f1"),
                 "app/Versions/1/framework"),
                ("a file the manifest does not name", lambda: write(framework + ".dylib", ""),
                 lambda: os.remove(framework + ".dylib"), "app/Versions/1/framework.dylib"),
                ("a missing file", lambda: os.remove(framework), lambda: write(framework, "f1"),
                 r"app/Versions/1/framework \(missing\)"),
                ("a changed link", lambda: (os.remove(os.path.join(folder, "app/Current")),
                                            os.symlink("Versions/2", os.path.join(folder, "app/Current"))),
                 lambda: (os.remove(os.path.join(folder, "app/Current")),
                          os.symlink("Versions/1", os.path.join(folder, "app/Current"))), r"app/Current \(link\)")):
            change()
            with self.assertRaisesRegex(driver.DriverError, "app differs from .*MANIFEST.json: " + expected, msg=name):
                driver.browser_binary(env)
            undo()
            self.assertEqual(driver.browser_binary(env), os.path.realpath(binary), name)
        write(helper, "#!/bin/ex\n")
        before, spawned, guards = set(driver.RUN_PIDS), [], []
        with mock.patch.dict(os.environ, env), mock.patch.object(driver.os, "posix_spawn", spawned.append), \
                mock.patch.object(driver, "guard_binary", lambda: guards.append(1) or "/usr/bin/false"):
            with self.assertRaisesRegex(driver.DriverError, "app differs.*app/Helpers/helper"):
                driver.Chrome()
        self.assertEqual((spawned, guards, driver.RUN_PIDS - before), ([], [], set()))  # nothing started

    def test_the_test_browsers_files_are_read_once_per_process_until_one_changes(self):
        # F4: kept by path, size, modification time, inode and change time; a file rewritten in place with its
        # size and modification time put back is read again.
        binary = fake_browser(self, files={"app/Helpers/helper": "#!/bin/sh\n"})
        env, helper = {driver.TEST_CHROME: binary}, os.path.join(os.path.dirname(binary), "Helpers", "helper")
        driver.browser_binary(env)
        reads, sha256 = [], hashlib.sha256
        # A file is read in chunks into sha256(); round 3: the pinned manifest is hashed at each start, sha256(bytes).
        with mock.patch.object(driver.hashlib, "sha256", lambda *a: (None if a else reads.append(1)) or sha256(*a)):
            driver.browser_binary(env)
            self.assertEqual(reads, [])  # nothing changed, nothing read again
            st = os.stat(helper)
            with open(helper, "w") as f:
                f.write("#!/bin/ex\n")  # the same size, the same inode
            os.utime(helper, ns=(st.st_atime_ns, st.st_mtime_ns))  # and the same modification time
            with self.assertRaisesRegex(driver.DriverError, "app/Helpers/helper"):
                driver.browser_binary(env)
        self.assertEqual(len(reads), 1)

    def test_service_rows_are_the_menu_bar_items_and_location_clients_of_the_run_only(self):
        # F1, F2: as macOS logged them on 2026-11-12 (ControlCenter 633, locationd 375).
        log = "\n".join([
            "Timestamp               Ty Process[PID:TID]",
            "2026-11-12 08:17:29.952 Df ControlCenter[633:1909] [com.apple.controlcenter:appStatusItems] Host "
            "properties initialized; (bid:org.chromium.Chromium-Item-0-4242). State(applicationItem: true)",
            "2026-11-12 08:17:29.953 Df ControlCenter[633:1909] [com.apple.controlcenter:appStatusItems] Starting to "
            "track host; (bid:com.example.other-Item-0-777)",
            "2026-11-12 08:17:29.954 Df ControlCenter[4242:1909] [com.apple.controlcenter:menu] Removing displayables "
            "[DisplayableAppStatusItem(4242ABCD, x)] 0x4242 42420 4242.5",
            "2026-11-12 08:17:27.732 Df locationd[375:e9588f] [com.apple.xpc:connection] [0xa5f69a700] activating "
            "connection: mach=false listener=false peer=true name=com.apple.locationd.desktop.registration.peer[4242]"
            ".0xa5f69a700",
            "2026-11-12 08:17:27.733 Df CoreLocationAgent[70482:e9f793] Sending registration to locationd - pid:4243, "
            "uuid:<private>, bundleId:(null)",
            '2026-11-12 08:17:27.735 Df locationd[375:e9588e] [com.apple.locationd.Core:Core] {"msg":"#registration '
            'UUID mapping", "pid":4244}',
            "2026-11-12 08:17:27.736 A  locationd[375:e9588f] CL: org.chromium.Chromium, client 9999",
            "2026-11-12 09:17:56.874 Df ControlCenter[633:1909] [com.apple.controlcenter:appStatusItems] Host "
            "properties initialized; (bid:org.chromium.Chromium-Item-0-31337)",
            "2026-11-12 09:17:56.875 Df Chromium[4242:1a2b] [com.apple.BoardServices:XPCErrors] [C:2] Alloc "
            "com.apple.controlcenter.statusitems",
        ])
        rows = log.splitlines()
        self.assertEqual(driver.service_rows(log, {4242}), [rows[1], rows[4]])
        self.assertEqual(driver.service_rows(log, {4243, 4244}), [rows[5], rows[6]])
        self.assertEqual(driver.service_rows(log, {4242}, {"org.chromium.Chromium"}), [rows[1], rows[4], rows[8]])
        self.assertEqual(driver.service_rows(log, {778, 424, 633, 9998}, {"org.example.TestBrowser"}), [])

    def test_a_uuid_in_a_controlcenter_line_names_no_pid_of_the_run(self):
        # Round 4 (starts30, 2026-11-22 11:43:28): ControlCenter's Now Playing request for the owner's player; the
        # UUID's group 8298 was a PID of the run, and the run was stopped for it. A status item still counts.
        log = "\n".join([
            "Timestamp               Ty Process[PID:TID]",
            "2026-11-22 11:43:28.484 Df ControlCenter[869:2138] [com.apple.amp.mediaremote:rr] Request: "
            "resolvePlayerPath<219BFE0B-8298-4322-A697-6B71D6EE1A76> for LOCL (Mac) com.brave.Browser (1446)",
            "2026-11-22 11:44:27.787 Df ControlCenter[869:2138] [com.apple.amp.mediaremote:rr] Request: "
            "playbackQueue<9FC9D30B-4E9D-4944-8259-059E4A6B6AE1 ControlCenter-869 /M/AF/A600.000000x600.000000/R[0",
            "2026-11-22 11:45:00.000 Df ControlCenter[869:2138] [com.apple.controlcenter:appStatusItems] Host "
            "properties initialized; (bid:org.example.other-Item-0-8298) 219BFE0B-8298-4322-A697-6B71D6EE1A76",
        ])
        rows = log.splitlines()
        self.assertEqual(driver.service_rows(log, {8298, 4322, 8259}), [rows[3]])
        self.assertEqual(driver.service_rows(log, {4322, 8259}), [])

    def test_service_log_reads_controlcenter_and_location_lines_for_the_whole_window(self):
        calls = []

        def run(argv, **kw):
            calls.append((argv, kw))
            return subprocess.CompletedProcess(argv, 0, "x")

        with mock.patch.object(driver.subprocess, "run", run):
            self.assertEqual(driver.service_log(1793479500.9, 1793479530.2), "x")
        stamp = lambda t: time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
        self.assertEqual(calls, [(["/usr/bin/log", "show", "--start", stamp(1793479500), "--end", stamp(1793479531),
                                   "--predicate", 'process == "ControlCenter" OR process == "locationd" OR '
                                   'process == "CoreLocationAgent" OR process == "useractivityd"', "--style",
                                   "compact"],
                                  {"check": True, "capture_output": True, "text": True})])

    def quiet_run_end(self, byhost, log):
        """check_run_end's world for one test: its own ByHost folder, no death, no report, no keychain line."""
        windows = []
        for name, value in (("BYHOST", byhost), ("_BASELINE", {}), ("DEATHS", []), ("BYHOST_NOTES", []),
                            ("REPORTS", temp_folder(self)), ("keychain_log", lambda start, end: ""),
                            ("service_log", lambda start, end: windows.append((start, end)) or log)):
            patch = mock.patch.object(driver, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        driver._BASELINE["byhost"] = driver.byhost_times()
        return windows

    def test_check_run_end_fails_on_a_menu_bar_item_of_the_run_and_names_the_byhost_change(self):
        # F1: ControlCenter's line is the proof; ByHost, rewritten with it, is named as its trace.
        byhost = temp_folder(self)
        entry = os.path.join(byhost, "com.apple.controlcenter.displayablemenuextras.X.plist")
        open(entry, "w").close()
        line = ("2026-11-12 08:17:29.952 Df ControlCenter[633:1909] [com.apple.controlcenter:appStatusItems] Host "
                "properties initialized; (bid:org.chromium.Chromium-Item-0-%d)" % os.getpid())
        windows = self.quiet_run_end(byhost, line)
        os.utime(entry, ns=(0, 0))  # as ControlCenter rewrote its menu bar list
        with self.assertRaisesRegex(driver.OwnerFilesChanged, r"STOP \(rule 10\).*menu bar item.*ByHost changed: "
                                    r"com\.apple\.controlcenter\.displayablemenuextras\.X\.plist.*Item-0-%d"
                                    % os.getpid()):
            driver.check_run_end(1793479500.0)
        self.assertEqual(windows[0][0], 1793479500.0)
        self.assertTrue(time.time() - 60 < windows[0][1] <= time.time())  # up to now

    def test_check_run_end_fails_on_a_location_registration_or_an_item_by_bundle_id(self):
        # F2: a registration of a PID the run added (a helper, Larsal); F1: the bundle id of a browser it started.
        other = max(driver.RUN_PIDS | {os.getpid()}) + 100000
        location = ("2026-11-12 08:17:27.733 Df CoreLocationAgent[70482:e9f793] Sending registration to locationd - "
                    "pid:%d, uuid:<private>" % other)
        self.quiet_run_end(temp_folder(self), location)
        driver.check_run_end(1793479500.0)  # not a PID of the run: no stop
        with mock.patch.object(driver, "RUN_PIDS", driver.RUN_PIDS | {other}):
            with self.assertRaisesRegex(driver.OwnerFilesChanged, "location registration.*pid:%d" % other):
                driver.check_run_end(1793479500.0)
        item = ("2026-11-12 09:17:56.874 Df ControlCenter[633:1909] [com.apple.controlcenter:appStatusItems] Host "
                "properties initialized; (bid:org.example.TestBrowser-Item-0-%d)" % other)
        with mock.patch.object(driver, "service_log", lambda start, end: item):
            driver.check_run_end(1793479500.0)  # another app's item
            with mock.patch.object(driver, "BUNDLES", {"org.example.TestBrowser"}):
                with self.assertRaisesRegex(driver.OwnerFilesChanged, "menu bar item.*TestBrowser-Item-0"):
                    driver.check_run_end(1793479500.0)

    def test_check_run_end_fails_on_a_handoff_activity_of_the_run(self):
        # Round 2: as useractivityd logged a test-browser start on 2026-11-12 (18:49:54, PID 77520).
        line = ("2026-11-12 18:49:54.024 Df useractivityd[16016:16b2844] [com.apple.useractivity:main] - Making "
                "B7AEF7F3-8E87-463A-BD44-31FE96C868F0/<private> into the currentItem from process <private>/%d")
        other = max(driver.RUN_PIDS | {os.getpid()}) + 100000
        self.quiet_run_end(temp_folder(self), line % other)
        driver.check_run_end(1793479500.0)  # another app's activity
        with mock.patch.object(driver, "service_log", lambda start, end: line % os.getpid()):
            with self.assertRaisesRegex(driver.OwnerFilesChanged, r"STOP \(rule 10\).*Handoff.*<private>/%d"
                                        % os.getpid()):
                driver.check_run_end(1793479500.0)

    def test_a_byhost_change_with_no_line_of_ours_is_the_owners_own_noted_not_failed(self):
        byhost = temp_folder(self)
        entry = os.path.join(byhost, "com.apple.commcenter.csidata.X.plist")
        open(entry, "w").close()
        self.quiet_run_end(byhost, "2026-11-12 08:17:29.953 Df ControlCenter[633:1909] [com.apple.controlcenter:"
                                   "appStatusItems] Starting to track host; (bid:com.example.other-Item-0-777)")
        os.utime(entry, ns=(0, 0))  # the owner's own service wrote it
        with mock.patch.object(sys, "stderr", io.StringIO()) as err:
            driver.check_run_end(1793479500.0)
        self.assertEqual(driver.BYHOST_NOTES, [["com.apple.commcenter.csidata.X.plist"]])
        self.assertIn("recorded, not a failure", err.getvalue())

    def test_check_run_end_reads_the_log_only_with_a_steady_clock(self):
        windows = self.quiet_run_end(temp_folder(self), "")
        with mock.patch.object(driver, "CLOCK_STEPS", [time.time()]):
            with self.assertRaisesRegex(driver.DriverError, "clock was changed during the run"):
                driver.check_run_end(time.time() - 1)
        self.assertEqual(windows, [])
        driver.check_run_end(time.time() - 1)
        self.assertEqual(len(windows), 1)

    def test_the_suite_run_ends_with_check_run_end(self):
        calls = []
        with mock.patch.object(driver, "check_run_end", calls.append):
            tearDownModule()
        self.assertEqual(calls, [RUN["start"]])

    def test_every_suite_ends_with_check_run_end_for_its_whole_run(self):
        # Round 2: the extension, popup and channel vector suites end the same way (F1, F2, F5).
        import importlib
        for name in ("test_extension", "test_popup", "test_channel_vectors"):
            suite, calls = importlib.import_module(name), []
            with mock.patch.object(driver, "check_run_end", calls.append), \
                    mock.patch.dict(suite.RUN, {"start": 1793479500.0}):
                suite.tearDownModule()
            self.assertEqual(calls, [1793479500.0], name)

    # Round 3 (2026-11-17): the Checkers' C1R2 and C2 findings and the lead's rulings.

    def test_the_sandbox_allows_writes_only_in_the_runs_own_folders(self):
        # C2-01: an allow-list, so no folder the owner can write is left out. sandbox_check asks the sandbox of a
        # live process (nothing is written or logged); its answers are calibrated by real writes inside the same
        # profile, each outside the owner's folders. It answers "denied" for any path that does not exist, even
        # in an allowed folder, so it is asked only about paths that exist: a wall's own folder or file (a path
        # rule that denies the folder denies everything under it but the allowed folders, all under /tmp).
        # The run root, and a folder of no run beside it; real paths, as the kernel names them to the sandbox.
        root, beside = os.path.realpath(temp_folder(self)), os.path.realpath(temp_folder(self))
        own = [os.path.join(root, part) for part in ("x", "home/x", "tmp/x", "home/" + driver.PROFILE + "/Default/x",
                                                    "home/Library/Application Support/Chromium/Crashpad/new/x",
                                                    "home/Library/Caches/Chromium/x")]
        for path in own:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()
        kept = os.path.join(beside, "kept")
        with open(kept, "w") as f:
            f.write("kept")
        profile = driver.sandbox_profile((root,))
        tried = probe(driver.sandboxed([sys.executable, "-I", "-c", WRITE_PROBE, root, beside, kept], profile))
        self.assertEqual(tried, {"create-own": "written", "create-beside": "EPERM", "data-beside": "EPERM",
                                 "unlink-beside": "EPERM", "dev-null": "written"})
        with open(kept) as f:
            self.assertEqual(f.read(), "kept")
        self.assertEqual(os.listdir(beside), ["kept"])
        sleeper = sandboxed_sleep(self, profile)
        ops = ("file-write-data", "file-write-create", "file-write-unlink")
        denied = lambda path: [denies_write(sleeper.pid, op, path) for op in ops]
        self.assertEqual([denied(p) for p in (os.path.join(root, "home", "written"), os.path.join(root, "home"),
                                              beside, kept)],
                         [[False] * 3, [False] * 3, [True] * 3, [True] * 3])  # as the real tries
        self.assertEqual([p for p in own if any(denied(p))], [])
        self.assertFalse(denies_write(sleeper.pid, "file-write-data", "/dev/null"))
        per_user = os.path.realpath(driver.USER_FOLDERS)
        walls = ["/opt/homebrew", "/opt/homebrew/bin", "/opt/homebrew/bin/brew", "/usr/local", "/Users/Shared",
                 "/Applications", "/Library", driver.REAL_HOME, os.path.join(driver.REAL_HOME, "Library"),
                 os.path.join(driver.REAL_HOME, "Library/Preferences"), os.path.join(per_user, "T"),
                 os.path.join(per_user, "C"), os.path.dirname(root)]
        # Round 4 (C1R3-07): a missing wall is asked at its nearest existing parent, and each substitution is named.
        notes = []
        asked = wall_paths(walls, notes)
        for note in notes:
            print("note: " + note, file=sys.stderr)
        self.assertIn("/private/tmp", asked)
        self.assertEqual([(w, a) for w, a in zip(walls, asked) if not all(denied(a))], [])

    def test_the_sandbox_lets_out_only_the_demo_servers_port(self):
        # C2-03: a host in a profile can only be "*" or "localhost", and "localhost" is every address of this Mac,
        # 0.0.0.0, :: and fe80::1 on any interface; so the rule narrows by port, and the resolver rules and the
        # socket check hold the rest. No packet is sent: EPERM is the sandbox's answer.
        # Round 4 (C1R3-01): the rule is "tcp" ("ip" let UDP out to every address it calls localhost, "tcp4" would
        # refuse ::1). So UDP is refused on every address and port (connect() on lo0 sends nothing), and what works
        # is TCP to listeners of this test on 127.0.0.1 and ::1 on the port; on another port, or to the IPv4-mapped
        # ::ffff:127.0.0.1 (recorded, C2R3-05), it is refused. TCP to an address this Mac does not hold is never
        # tried. With no sandbox each of these TCP connections is made: the EPERMs are the sandbox's.
        port, other = tcp_listeners(self), tcp_listeners(self)
        profile = driver.sandbox_profile(ports=(port,))
        interfaces = [name for _, name in socket.if_nameindex() if name in ("en0", "utun4")]
        hosts = ["127.0.0.1", "::1", "0.0.0.0", "::", "fe80::1%lo0", "192.0.2.1"] + ["fe80::1%" + i for i in interfaces]
        hosts += [a for a in own_addresses() if a not in hosts]  # the Mac's own LAN and link-local addresses
        specs = ["%s %d" % (host, p) for host in hosts for p in (port, other)]
        answers = probe(driver.sandboxed([sys.executable, "-I", "-c", UDP_PROBE] + specs, profile))
        self.assertEqual([s for s in specs if answers[s] != "EPERM"], [])  # no UDP at all
        tcp = ["127.0.0.1 %d" % port, "::1 %d" % port, "127.0.0.1 %d" % other, "::1 %d" % other,
               "::ffff:127.0.0.1 %d" % port]
        self.assertEqual(probe(driver.sandboxed([sys.executable, "-I", "-c", TCP_PROBE] + tcp, profile)),
                         dict(zip(tcp, ["connected", "connected", "EPERM", "EPERM", "EPERM"])))
        self.assertEqual(probe([sys.executable, "-I", "-c", TCP_PROBE] + tcp), dict.fromkeys(tcp, "connected"))
        self.assertEqual([s for s, a in probe(driver.sandboxed([sys.executable, "-I", "-c", TCP_PROBE] + tcp))
                          .items() if a != "EPERM"], [])  # no demo server: no address at all
        self.assertEqual([s for s, a in probe(driver.sandboxed([sys.executable, "-I", "-c", UDP_PROBE] + specs))
                          .items() if a != "EPERM"], [])

    def test_the_demo_port_goes_through_whatever_its_number(self):
        # Round 4: with the port's allow before the unix-socket lines, the sandbox refused TCP on the allowed port
        # for about one port in ten, the same ports every time (32 of 300 in r4/probes/tcp-sweep-1.json, 26 of 200
        # in tcp-ports-1.json); that was every refused page load of round 4. Now the unix-socket lines come first.
        # For each port the old order refused (those free here) and 20 more: TCP to listeners of this test on
        # 127.0.0.1 and ::1 on it connects, and on another port of this test it is EPERM.
        folders = (driver.run_root("larsal-chrome-"), driver.run_root("larsal-ext-"))  # named as a run's
        for folder in folders:
            self.addCleanup(shutil.rmtree, folder, True)
        other = tcp_listeners(self)
        ports = [p for p in REFUSED_BEFORE if listen_on(self, p)]
        self.assertGreaterEqual(len(ports), 6, "too few of the ports the old order refused are free here")
        ports += [tcp_listeners(self) for _ in range(20)]
        wrong = {}
        for port in ports:
            tcp = ["127.0.0.1 %d" % port, "::1 %d" % port, "127.0.0.1 %d" % other]
            got = probe(driver.sandboxed([sys.executable, "-I", "-c", TCP_PROBE] + tcp,
                                         driver.sandbox_profile(folders, (port,))))
            if [got[s] for s in tcp] != ["connected", "connected", "EPERM"]:
                wrong[port] = got
        self.assertEqual(wrong, {})

    def test_the_socket_check_takes_only_127_0_0_1_and_ipv6_loopback_as_loopback(self):
        # C2-03: what the sandbox's "localhost" lets through on the demo server's port fails the run here.
        lsof = ("p4242\nf5\nn127.0.0.1:50000->127.0.0.1:8443\nf6\nn[::1]:50001->[::1]:8443\nf7\nn*:*\n"
                "f8\nn192.0.2.44:50002->192.0.2.44:8443\nf9\nn[fe80:e::1]:50003->[fe80:e::1]:8443\n"
                "f10\nn0.0.0.0:8443\nf11\nn[::]:8443\nf12\nnlocalhost:8443\nf13\nn127.0.0.2:8443\n"
                "f14\nn127.0.0.1:50004->198.51.100.2:8443\n")
        with mock.patch.object(driver.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, lsof)):
            self.assertEqual(driver.outside_loopback([4242]), [
                "192.0.2.44:50002->192.0.2.44:8443", "[fe80:e::1]:50003->[fe80:e::1]:8443", "0.0.0.0:8443",
                "[::]:8443", "localhost:8443", "127.0.0.2:8443", "127.0.0.1:50004->198.51.100.2:8443"])

    def test_no_browser_but_the_pinned_test_browser_is_started(self):
        # C2-12: no fallback. With the variable unset or empty, or a path anywhere but the test browsers' folder
        # (/Applications included, or the same bytes elsewhere), the driver refuses before anything starts.
        binary = fake_browser(self)  # its folder is the test browsers' folder for this test
        elsewhere = os.path.join(temp_folder(self), "browser")
        shutil.copy2(binary, elsewhere)
        for environ, refusal in (({}, "LARSAL_TEST_CHROME is not set"), ({driver.TEST_CHROME: ""}, "is not set"),
                                 ({driver.TEST_CHROME: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
                                  "is not under"), ({driver.TEST_CHROME: elsewhere}, "is not under")):
            with self.assertRaisesRegex(driver.DriverError, refusal, msg=str(environ)):
                driver.browser_binary(environ)
        before, spawned, guards = set(driver.RUN_PIDS), [], []
        with mock.patch.dict(os.environ), mock.patch.object(driver.os, "posix_spawn", spawned.append), \
                mock.patch.object(driver, "guard_binary", lambda: guards.append(1) or "/usr/bin/false"):
            os.environ.pop(driver.TEST_CHROME, None)
            with self.assertRaisesRegex(driver.DriverError, "is not set"):
                driver.Chrome()
        self.assertEqual((spawned, guards, driver.RUN_PIDS - before), ([], [], set()))  # nothing started

    def test_a_folder_whose_manifest_matches_only_its_own_files_is_refused(self):
        # C2-12: MANIFEST.json no longer vouches for itself; the driver pins its SHA-256.
        binary = fake_browser(self)  # a manifest that names the stand-in, pinned for this test
        environ = {driver.TEST_CHROME: binary}
        self.assertEqual(driver.browser_binary(environ), os.path.realpath(binary))
        with mock.patch.object(driver, "MANIFEST_SHA256", PINNED):  # the driver's own pin, the real browser's
            with self.assertRaisesRegex(driver.DriverError, "is not the pinned manifest"):
                driver.browser_binary(environ)

    def test_the_whole_app_folder_is_checked_for_a_binary_in_contents_macos(self):
        # C2-05: laid out like the test browser's app (the launcher in Contents/MacOS, a framework with its
        # Versions/Current link and a helper app in it): the walk up to the ".app" folder is what reaches them.
        framework = "Test.app/Contents/Frameworks/Test Framework.framework"
        helper = framework + "/Versions/1.0/Helpers/Test Helper.app/Contents/MacOS/Test Helper"
        binary = fake_browser(self, binary="Test.app/Contents/MacOS/Test",
                              files={"Test.app/Contents/Info.plist": "<plist/>", helper: "#!/bin/sh\n",
                                     framework + "/Versions/1.0/Test Framework": "f1"},
                              links={framework + "/Versions/Current": "1.0"})
        folder, environ = binary.rsplit("/Test.app/", 1)[0], {driver.TEST_CHROME: binary}
        self.assertEqual(driver.browser_binary(environ), os.path.realpath(binary))
        for path, text, undo in ((helper, "#!/bin/ex\n", "#!/bin/sh\n"),
                                 (framework + "/Versions/1.0/Test Framework", "f2", "f1"),
                                 (framework + "/Versions/1.0/Libraries/extra.dylib", "", None)):
            full = os.path.join(folder, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(text)
            with self.assertRaisesRegex(driver.DriverError, "app differs from .*MANIFEST.json: " + re.escape(path)):
                driver.browser_binary(environ)
            if undo is None:
                os.remove(full)
            else:
                with open(full, "w") as f:
                    f.write(undo)
        self.assertEqual(driver.browser_binary(environ), os.path.realpath(binary))

    # Round 4 (2026-11-22): the Checkers' C1R3 and C2R3 findings and the lead's rulings.

    def test_the_sandbox_walls_every_unix_socket_outside_the_runs_folders(self):
        # C2R3-02: connect and bind only under the run's own folders. Real tries inside the profile, to listeners of
        # this test only: one in the run's folder (its /tmp form too), one in another folder of this test that is
        # no run's. sandbox_check, calibrated by them on a live process in the same profile, then asks (no connect,
        # no report) for the system's sockets that exist here: syslog, usbmuxd, vpncontrol, mDNSResponder,
        # launchd's Listeners and the owner's docker socket.
        run, other = os.path.realpath(temp_folder(self)), os.path.realpath(temp_folder(self))
        for folder in (run, other):
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(os.path.join(folder, "l.sock"))
            listener.listen(4)
            self.addCleanup(listener.close)
        profile = driver.sandbox_profile((run,))
        tries = ["connect " + os.path.join(run, "l.sock"), "connect /tmp" + os.path.join(run, "l.sock")[12:],
                 "connect " + os.path.join(other, "l.sock"), "bind " + os.path.join(run, "b.sock"),
                 "bind " + os.path.join(other, "b.sock")]
        self.assertEqual(probe(driver.sandboxed([sys.executable, "-I", "-c", UNIX_PROBE] + tries, profile)),
                         dict(zip(tries, ["connected", "connected", "EPERM", "bound", "EPERM"])))
        self.assertEqual(os.listdir(other), ["l.sock"])  # nothing bound there
        free = [t.replace("b.sock", "f.sock") for t in tries]
        self.assertEqual(probe([sys.executable, "-I", "-c", UNIX_PROBE] + free),
                         dict(zip(free, ["connected", "connected", "connected", "bound", "bound"])))
        sleeper = sandboxed_sleep(self, profile)
        ask = lambda path: driver._SANDBOX_CHECK(sleeper.pid, b"network-outbound", PATH_FILTER | NO_REPORT,
                                                 path.encode())
        self.assertEqual([ask(os.path.join(run, "l.sock")), ask(os.path.join(other, "l.sock"))], [0, 1])  # as tried
        system = ["/private/var/run/syslog", "/private/var/run/usbmuxd", "/private/var/run/vpncontrol.sock",
                  "/private/var/run/mDNSResponder", os.path.join(driver.REAL_HOME, ".docker/run/docker.sock")]
        system += [os.path.join(p, "Listeners") for p in [os.path.join("/private/var/run", n) for n in
                                                          os.listdir("/private/var/run")
                                                          if n.startswith("com.apple.launchd.")]]
        present = [p for p in system if os.path.lexists(p)]  # only what exists here can be asked
        print("note: system sockets asked: %s; missing here: %s" % (present, sorted(set(system) - set(present))),
              file=sys.stderr)
        self.assertIn("/private/var/run/syslog", present)
        self.assertEqual([p for p in present if ask(p) != 1], [])

    def test_the_unix_bind_wall_is_its_own_rule_not_only_the_write_wall(self):
        # Round 4 (mutant M2b stayed green): a bind outside the run's folders is EPERM under the write wall too, so
        # a real bind cannot show the bind rule. sandbox_check (no report) asks each rule apart, on a live process in
        # the profile, for paths that exist (it answers 1 for a missing one; r4/probes/bind-check-2.json).
        run, other = os.path.realpath(temp_folder(self)), os.path.realpath(temp_folder(self))
        paths = [os.path.join(run, "b.sock"), os.path.join(other, "b.sock")]
        for path in paths:
            open(path, "w").close()
        sleeper = sandboxed_sleep(self, driver.sandbox_profile((run,)))
        ask = lambda op: [driver._SANDBOX_CHECK(sleeper.pid, op, PATH_FILTER | NO_REPORT, p.encode()) for p in paths]
        self.assertEqual(ask(b"network-bind"), [0, 1])
        self.assertEqual(ask(b"file-write-create"), [0, 1])

    def test_a_unix_socket_in_each_of_the_runs_folders_is_reached_not_only_the_first(self):
        # Round 4 (extension-1): a run has two folders, its own and the run root that holds the test HOME (where a
        # suite's stand-in Larsal listens). With both in one allow the kernel let only the first through.
        first, second = sorted(os.path.realpath(temp_folder(self)) for _ in range(2))
        other = os.path.realpath(temp_folder(self))
        for folder in (first, second, other):
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(os.path.join(folder, "l.sock"))
            listener.listen(4)
            self.addCleanup(listener.close)
        tries = ["connect " + os.path.join(f, "l.sock") for f in (first, second, other)] + \
                ["bind " + os.path.join(f, "b.sock") for f in (first, second, other)]
        self.assertEqual(probe(driver.sandboxed([sys.executable, "-I", "-c", UNIX_PROBE] + tries,
                                                driver.sandbox_profile((second, first)))),
                         dict(zip(tries, ["connected", "connected", "EPERM", "bound", "bound", "EPERM"])))

    def test_the_echo_host_runs_under_the_suites_own_interpreter_by_its_full_path(self):
        # C2R3-01: its own first line names /usr/bin/python3, an xcrun shim (a cold lookup writes the owner's
        # T/xcrun_db); the installed program names the interpreter of this suite instead.
        home = os.path.realpath(temp_folder(self))
        driver.install_echo_host(home, "a" * 32)
        with open(os.path.join(home, "echo.py")) as f, open(os.path.join(driver.HERE, "echo-host", "echo.py")) as g:
            installed, source = f.read(), g.read()
        self.assertEqual(installed.split("\n", 1)[0], "#!%s -IB" % sys.executable)
        self.assertTrue(os.path.isabs(sys.executable) and not sys.executable.startswith("/usr/bin/"), sys.executable)
        self.assertEqual(installed.split("\n", 1)[1], source.split("\n", 1)[1])  # the rest as it is

    def test_unix_sockets_outside_names_the_bound_sockets_outside_the_folders_only(self):
        # C2R3-02: lsof -U names a socket by the path it is bound to (a client shows only "->0x..." for its peer).
        inside, outside = temp_folder(self), temp_folder(self)
        for folder in (inside, outside):
            listener = socket.socket(socket.AF_UNIX)
            listener.bind(os.path.join(folder, "s.sock"))
            listener.listen(4)
            self.addCleanup(listener.close)
        client = socket.socket(socket.AF_UNIX)
        client.connect(os.path.join(outside, "s.sock"))
        self.addCleanup(client.close)
        found = [os.path.realpath(n) for n in driver.unix_sockets_outside([os.getpid()], [inside])
                 if "/larsal-driver-test-" in n]
        self.assertEqual(found, [os.path.realpath(os.path.join(outside, "s.sock"))])
        self.assertEqual([n for n in driver.unix_sockets_outside([os.getpid()], [inside, outside])
                          if "/larsal-driver-test-" in n], [])
        lsof = "p4242\nf5\nn/private/tmp/larsal-chrome-x/tmp/s.sock\nf6\nn->0x1234\nf7\nn/private/var/run/x.sock\n"
        with mock.patch.object(driver.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 0, lsof)):
            self.assertEqual(driver.unix_sockets_outside([4242], ["/tmp/larsal-chrome-x"]), ["/private/var/run/x.sock"])

    def test_a_missing_wall_is_asked_at_its_nearest_existing_parent_and_named(self):
        # C1R3-07: sandbox_check reads a missing path as denied, so a missing wall is asked at its nearest existing
        # parent (here a stand-in: a folder of no run, with the missing wall two levels under it), and named.
        root, beside = os.path.realpath(temp_folder(self)), os.path.realpath(temp_folder(self))
        missing = os.path.join(beside, "homebrew", "bin")
        notes = []
        self.assertEqual(wall_paths([missing, beside, "/private/tmp"], notes), [beside, beside, "/private/tmp"])
        self.assertEqual(notes, ["%s is missing here: asked its nearest existing parent %s" % (missing, beside)])
        sleeper = sandboxed_sleep(self, driver.sandbox_profile((root,)))
        self.assertTrue(denies_write(sleeper.pid, "file-write-create", beside))
        self.assertTrue(denies_write(sleeper.pid, "file-write-create", missing))  # what it would read: proves nothing
        self.assertFalse(denies_write(sleeper.pid, "file-write-create", root))

    def test_a_browser_in_a_sibling_folder_with_the_same_prefix_is_refused(self):
        # C1R3-04, C2R3-08: tools/chromium-old/ is not under tools/chromium/, even with its manifest as the pin.
        parent = temp_folder(self)
        tools = os.path.join(parent, "chromium")
        os.makedirs(tools)
        binary = fake_browser(self)  # its manifest is pinned for this test
        sibling = tools + "-old"
        shutil.move(os.path.dirname(os.path.dirname(binary)), sibling)
        binary = os.path.join(sibling, "app", "browser")
        with mock.patch.object(driver, "TEST_BROWSERS", tools):
            with self.assertRaisesRegex(driver.DriverError, "is not under .*/chromium, where the pinned test browser is"):
                driver.browser_binary({driver.TEST_CHROME: binary})
        with mock.patch.object(driver, "TEST_BROWSERS", sibling):  # the same files where the pin points: started
            self.assertEqual(driver.browser_binary({driver.TEST_CHROME: binary}), os.path.realpath(binary))

    def test_only_a_run_root_this_driver_process_made_or_marked_is_accepted(self):
        # C1R3-06: a folder under /tmp made elsewhere (another agent's root) is refused before anything is written
        # in it; a marker of another process, or with another token, too; mark_root marks only a folder of this
        # user under /tmp (/var/empty: no write even if that check broke).
        made = driver.run_root("larsal-driver-test-")
        self.addCleanup(shutil.rmtree, made, True)
        self.assertEqual(driver.check_run_root(made), os.path.realpath(made))
        other = tempfile.mkdtemp(prefix="larsal-driver-test-", dir="/tmp")
        self.addCleanup(shutil.rmtree, other, True)
        with self.assertRaisesRegex(driver.DriverError, "was not made by this driver process"):
            driver.check_run_root(other)
        marker = os.path.join(other, driver.MARKER)
        for text in ("%d %s\n" % (os.getpid() + 1, driver.TOKEN), "%d %s\n" % (os.getpid(), "0" * 32), ""):
            with open(marker, "w") as f:
                f.write(text)
            with self.assertRaisesRegex(driver.DriverError, "holds no run marker of it", msg=text):
                driver.check_run_root(other)
        os.remove(marker)
        driver.mark_root(other)
        self.assertEqual(driver.check_run_root(other), os.path.realpath(other))
        with self.assertRaisesRegex(driver.DriverError, "only a folder of this user under /tmp"):
            driver.mark_root("/var/empty")


class TestBrowserTests(unittest.TestCase):
    """The driver's checks on a run, with FAKE_BROWSER as the test browser."""

    def start(self, **kwargs):
        self.binary = fake_browser(self)
        with mock.patch.dict(os.environ, {driver.TEST_CHROME: self.binary}):
            chrome = driver.Chrome(**kwargs)
        self.addCleanup(chrome.close)
        return chrome

    def test_the_driver_starts_the_test_browser_inside_its_sandbox(self):
        chrome = self.start()
        self.assertEqual(chrome.binary, os.path.realpath(self.binary))
        self.assertIn(chrome.binary + " --headless=new", driver.command_line(chrome.pid))  # the same PID
        for name in ("com.apple.cfprefsd.agent", "com.apple.lsd.modifydb", "com.apple.tccd", "com.apple.pasteboard.1"):
            self.assertTrue(driver.denies_lookup(chrome.pid, name), name)
        self.assertFalse(driver.denies_lookup(chrome.pid, "com.apple.coreservices.launchservicesd"))
        self.assertFalse(driver.denies_lookup(os.getpid(), "com.apple.cfprefsd.agent"))  # this test is outside
        chrome.close()

    def test_a_browser_outside_the_drivers_sandbox_is_stopped(self):
        before, made = set(driver.RUN_PIDS), []
        self.addCleanup(lambda: [chrome.close() for chrome in made])  # only when the driver lets it run
        with mock.patch.object(driver, "sandboxed", lambda argv, profile=None: list(argv)):
            with self.assertRaisesRegex(driver.DriverError, "not inside the driver's sandbox") as e:
                made.append(self.start())
        drop_kept_in(self, e.exception)  # round 4: this failure on purpose keeps its connects too
        ran = driver.RUN_PIDS - before
        self.assertTrue(ran)
        self.assertEqual([p for p in ran if driver._alive(p)], [])

    def test_an_owner_file_that_changes_while_the_browser_runs_stops_it_at_once(self):
        watched = os.path.join(temp_folder(self), "watched")
        open(watched, "w").close()
        chrome = self.start()
        chrome.before = dict(chrome.before, **{watched: os.stat(watched).st_mtime_ns})
        time.sleep(1)
        self.assertFalse(chrome._exited(0.1), "with no change the browser runs on")
        os.utime(watched, ns=(0, 0))  # as cfprefsd wrote the owner's Preferences for the browser
        self.assertTrue(chrome._exited(3), "a change of an owner file must stop the browser at once")
        with mock.patch.object(driver, "REPORT_WAIT", 1), \
                self.assertRaisesRegex(driver.OwnerFilesChanged, "watched") as e:
            chrome.close()
        self.assertNotIn("died by signal", str(e.exception))  # the driver's own stop is no crash

    def test_a_crash_report_of_the_browser_fails_the_run(self):
        reports = temp_folder(self)
        with mock.patch.object(driver, "REPORTS", reports):
            chrome = self.start()
            for name in ("Chromium Helper (Renderer)-2026-11-12-070000.ips", "Other-2026-11-12-070000.ips"):
                open(os.path.join(reports, name), "w").close()  # as macOS names them
            with self.assertRaisesRegex(driver.OwnerFilesChanged, r"crash reports.*Chromium Helper \(Renderer\)") as e:
                chrome.close()
        self.assertNotIn("Other-", str(e.exception))

    def test_a_crash_report_macos_writes_after_the_crash_still_fails_the_run(self):
        # 2026-11-12: the test browser aborted at start three times; macOS wrote each report 8 to 21 s later.
        reports = temp_folder(self)
        late = os.path.join(reports, "Chromium-2026-11-12-064750.ips")
        with mock.patch.object(driver, "REPORTS", reports):
            chrome = self.start()
            os.kill(chrome.pid, signal.SIGTERM)  # our own child, by a signal the driver did not send; no report of its own
            timer = threading.Timer(5, lambda: open(late, "w").close())
            timer.start()
            self.addCleanup(timer.cancel)
            with self.assertRaisesRegex(driver.OwnerFilesChanged,
                                        r"crash reports.*Chromium-2026-11-12-064750\.ips.*died by signal 15"):
                chrome.close()

    def test_a_browser_that_dies_by_a_signal_the_driver_did_not_send_fails_the_run(self):
        with mock.patch.object(driver, "REPORTS", temp_folder(self)), mock.patch.object(driver, "REPORT_WAIT", 1):
            chrome = self.start()
            os.kill(chrome.pid, signal.SIGTERM)  # our own child
            with self.assertRaisesRegex(driver.DriverError, "died by signal 15, which the driver did not send"):
                chrome.close()

    def test_a_socket_of_the_run_beyond_loopback_fails_the_run(self):
        chrome = self.start()
        pid, seen = chrome.pid, []
        with mock.patch.object(driver, "outside_loopback", lambda pids: seen.append(pids) or ["192.0.2.1:443"]):
            with self.assertRaisesRegex(driver.DriverError, r"STOP \(rule 7\).*192\.0\.2\.1:443"):
                chrome.close()
        self.assertIn(pid, seen[0])  # listed while it ran

    def test_the_runs_watch_notes_a_change_of_the_system_clock(self):
        chrome = self.start()
        with mock.patch.object(driver, "CLOCK_STEPS", []) as steps, \
                mock.patch.object(driver, "CLOCK", driver.CLOCK + 3600):  # as if set forward an hour
            deadline = time.monotonic() + 3
            while not steps and time.monotonic() < deadline:
                time.sleep(0.1)
            chrome.close()
        self.assertTrue(steps)

    # Round 2 (2026-11-12): the Checker's F3 and F5.

    def test_a_start_spawns_the_browser_in_the_sandbox_with_its_walls_and_network_rules(self):
        # F3: the argv a start hands to posix_spawn, not only what sandbox_profile returns.
        calls, spawn = [], os.posix_spawn

        def record(path, argv, env, **kwargs):
            calls.append((path, list(argv), dict(env)))
            return spawn(path, argv, env, **kwargs)

        # Round 3: the demo server's port is the only one out (C2-03); writes only in the run's folder (C2-01).
        # Round 4: TCP only (C1R3-01); no unix-domain socket outside the run's folder, to connect to or to bind
        # (C2R3-02); a NetLog in the run's folder (C1R3-03); the run's folder as LARSAL_TEST_INSTANCE_DIR and no
        # DEVELOPER_DIR (C2R3-01). The unix-socket lines first and the IP lines last (round 4, driver-2: in the other
        # order the sandbox refused TCP on about one port in ten).
        sites = types.SimpleNamespace(port=8443, spki="SPKI")  # stands in for TestSites: the stand-in connects nowhere
        with mock.patch.object(driver.os, "posix_spawn", record), mock.patch.dict(os.environ,
                                                                                  {"DEVELOPER_DIR": driver.XCODE}):
            chrome = self.start(sites=sites)
        (path, argv, env), = calls
        folder = os.path.realpath(chrome.folder)
        profile = ("(version 1)\n(allow default)\n(deny network-outbound (remote unix-socket))\n"
                   "(deny network-bind (local unix-socket))\n"
                   '(allow network-outbound (remote unix-socket (subpath "%s")))\n'
                   '(allow network-bind (local unix-socket (subpath "%s")))\n'
                   "(deny network-outbound (remote ip))\n"
                   '(allow network-outbound (remote tcp "localhost:8443"))\n'
                   '(deny network-inbound (local ip "*:*"))\n'
                   '(deny file-write*)\n(allow file-write* (subpath "%s"))\n(allow file-write* (literal "/dev/null"))\n'
                   "(deny mach-lookup %s)\n" % (folder, folder, folder, driver.SERVICES))
        self.assertEqual((path, argv[:3]), ("/usr/bin/sandbox-exec", ["/usr/bin/sandbox-exec", "-p", profile]))
        self.assertEqual(argv[3:], [chrome.binary] + driver.chrome_flags(chrome.profile, "SPKI")
                         + ["--log-net-log=" + os.path.join(chrome.folder, "net.json"), "about:blank"])
        self.assertEqual((env["HOME"], env["CFFIXED_USER_HOME"], env["TMPDIR"], env["LARSAL_TEST_INSTANCE_DIR"]),
                         (chrome.home, chrome.home, os.path.join(chrome.folder, "tmp"), folder))
        self.assertNotIn("DEVELOPER_DIR", env)
        chrome.close()

    def test_the_runs_sockets_are_listed_while_the_browser_still_runs(self):
        # F3: lsof sees only live processes, so close() lists the sockets before Browser.close.
        chrome = self.start()
        pid, running = chrome.pid, []

        def spy(pids):
            try:
                running.append(pid in pids and os.waitpid(pid, os.WNOHANG) == (0, 0))
            except ChildProcessError:
                running.append(False)
            return []

        with mock.patch.object(driver, "outside_loopback", spy):
            chrome.close()
        self.assertEqual(running, [True])

    def test_a_late_crash_report_fails_the_next_run_and_the_suite_end(self):
        # F5: one baseline per suite process, so a later start never takes an earlier run's report into its own.
        reports = temp_folder(self)
        with mock.patch.object(driver, "REPORTS", reports), mock.patch.object(driver, "_BASELINE", {}), \
                mock.patch.object(driver, "DEATHS", []):
            self.start().close()  # no report yet: it passes
            open(os.path.join(reports, "Chromium Helper (GPU)-2026-11-12-190000.ips"), "w").close()  # after the close
            chrome = self.start()
            with self.assertRaisesRegex(driver.OwnerFilesChanged, r"crash reports.*Chromium Helper \(GPU\)"):
                chrome.close()
            with mock.patch.object(driver, "service_log", lambda start, end: ""), \
                    mock.patch.object(driver, "keychain_log", lambda start, end: ""):
                with self.assertRaisesRegex(driver.OwnerFilesChanged, r"crash reports.*Chromium Helper \(GPU\)"):
                    driver.check_run_end(time.time() - 1)

    def test_the_suite_end_waits_for_a_late_report_only_after_a_run_that_died(self):
        # F5: after the last close; macOS wrote the test browser's reports 8 to 21 s after the crash.
        reports = temp_folder(self)
        late = os.path.join(reports, "Chromium-2026-11-12-190500.ips")
        for name, value in (("REPORTS", reports), ("_BASELINE", {}), ("REPORT_WAIT", 20),
                            ("service_log", lambda start, end: ""), ("keychain_log", lambda start, end: "")):
            patch = mock.patch.object(driver, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        driver.new_crash_reports()  # the suite's baseline
        start = time.monotonic()
        with mock.patch.object(driver, "DEATHS", []):
            driver.check_run_end(time.time() - 1)  # no death: no wait
        self.assertLess(time.monotonic() - start, 10)
        timer = threading.Timer(2, lambda: open(late, "w").close())
        timer.start()
        self.addCleanup(timer.cancel)
        start = time.monotonic()
        with mock.patch.object(driver, "DEATHS", [("signal", 15)]):
            with self.assertRaisesRegex(driver.OwnerFilesChanged, r"Chromium-2026-11-12-190500\.ips"):
                driver.check_run_end(time.time() - 1)
        self.assertLess(time.monotonic() - start, 15)  # it stops waiting at the report

    def test_a_death_by_a_signal_the_driver_did_not_send_makes_the_suite_end_wait_too(self):
        # F5: close() waits for this run's report; check_run_end waits again after the suite's last close.
        with mock.patch.object(driver, "REPORTS", temp_folder(self)), mock.patch.object(driver, "REPORT_WAIT", 1), \
                mock.patch.object(driver, "DEATHS", []):
            chrome = self.start()
            os.kill(chrome.pid, signal.SIGTERM)  # our own child
            with self.assertRaisesRegex(driver.DriverError, "died by signal 15"):
                chrome.close()
            self.assertEqual(driver.DEATHS, [("signal", signal.SIGTERM)])

    def test_the_bundle_id_of_a_started_browser_is_kept_for_the_run_end(self):
        # F1: read from the Info.plist of the app that holds the binary; a binary in no app has none.
        app = os.path.join(temp_folder(self), "Test.app")
        os.makedirs(os.path.join(app, "Contents", "MacOS"))
        with open(os.path.join(app, "Contents", "Info.plist"), "wb") as f:
            f.write(b'<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key>'
                    b'<string>org.example.TestBrowser</string></dict></plist>')
        self.assertEqual(driver.bundle_id(os.path.join(app, "Contents", "MacOS", "browser")), "org.example.TestBrowser")
        with mock.patch.object(driver, "BUNDLES", set()), \
                mock.patch.object(driver, "bundle_id", lambda binary: "org.example.TestBrowser"):
            self.start().close()
            self.assertEqual(driver.BUNDLES, {"org.example.TestBrowser"})
        self.assertIsNone(driver.bundle_id(self.binary))  # the stand-in is in no app

    def kept_dumps(self):
        """The folders keep_dumps makes during this test; each is removed when the test ends, before any
        assertion can fail (C1R2-04)."""
        made, keep = [], driver.keep_dumps

        def keep_and_clean(home, dumps):
            made.append(keep(home, dumps))
            self.addCleanup(shutil.rmtree, made[-1], True)
            return made[-1]

        patch = mock.patch.object(driver, "keep_dumps", keep_and_clean)
        patch.start()
        self.addCleanup(patch.stop)
        return made

    def test_a_crash_dump_in_the_test_home_fails_the_run_and_is_kept_outside_it(self):
        # F5: Crashpad's own dump, listed before the test HOME is removed; an earlier run's dump is not this run's.
        made = self.kept_dumps()
        home = os.path.join(temp_folder(self), "home")
        pending = os.path.join(home, "Library/Application Support/Chromium/Crashpad/pending")
        os.makedirs(pending)
        open(os.path.join(pending, "old.dmp"), "w").close()
        with mock.patch.object(driver, "DEATHS", []):
            self.start(home=home).close()  # the old dump only: it passes
            chrome = self.start()
            pending = os.path.join(chrome.home, "Library/Application Support/Chromium/Crashpad/completed")
            os.makedirs(pending)
            with open(os.path.join(pending, "dump-1.dmp"), "w") as f:
                f.write("dump")
            with self.assertRaisesRegex(driver.DriverError, r"crash dumps \(kept in /tmp/larsal-crash-dumps-\w+\): "
                                        r"dump-1\.dmp") as e:
                chrome.close()
            self.assertEqual(len(driver.DEATHS), 1)  # check_run_end waits for a late report too
        kept = re.search(r"kept in (\S+)\)", str(e.exception)).group(1)
        self.assertEqual(made, [kept])
        with open(os.path.join(kept, "Library/Application Support/Chromium/Crashpad/completed/dump-1.dmp")) as f:
            self.assertEqual(f.read(), "dump")
        self.assertFalse(os.path.exists(chrome.home))  # the test HOME is gone, the dump is kept

    # Round 3 (2026-11-17): the Checkers' C1R2 and C2 findings and the lead's rulings.

    def test_a_crash_dump_in_crashpads_pending_or_new_folder_fails_the_run_too(self):
        # C2-04, C1R2-03: Crashpad writes a dump into new/, then moves it to pending/ (completed/ after an upload).
        made = self.kept_dumps()
        for part in ("pending", "new"):
            with mock.patch.object(driver, "DEATHS", []):
                chrome = self.start()
                folder = os.path.join(chrome.home, "Library/Application Support/Chromium/Crashpad", part)
                os.makedirs(folder)
                open(os.path.join(folder, "dump-%s.dmp" % part), "w").close()
                with self.assertRaisesRegex(driver.DriverError, r"crash dumps \(kept in .*\): dump-%s\.dmp" % part):
                    chrome.close()
        self.assertEqual(len(made), 2)

    def test_the_byhost_baseline_is_taken_once_per_suite_at_its_first_start(self):
        # C1R2-01: a ByHost change during the suite's first run is still seen at its end, after a later start.
        byhost = temp_folder(self)
        entry = os.path.join(byhost, "com.apple.controlcenter.displayablemenuextras.X.plist")
        open(entry, "w").close()
        for name, value in (("BYHOST", byhost), ("_BASELINE", {}), ("DEATHS", []), ("BYHOST_NOTES", []),
                            ("REPORTS", temp_folder(self)), ("keychain_log", lambda start, end: ""),
                            ("service_log", lambda start, end: "")):
            patch = mock.patch.object(driver, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.start().close()  # the suite's first start takes the baseline
        os.utime(entry, ns=(0, 0))  # as ControlCenter rewrote its menu bar list during that run
        self.start().close()
        with mock.patch.object(sys, "stderr", io.StringIO()):
            driver.check_run_end(time.time() - 1)
        self.assertEqual(driver.BYHOST_NOTES, [["com.apple.controlcenter.displayablemenuextras.X.plist"]])

    def test_close_lists_the_sockets_of_every_process_of_the_run(self):
        # C2-06: the network service, which tried remote *:443, is a helper; close() lists every PID pids() gives.
        chrome = self.start()
        main, helper, found, seen = chrome.pid, subprocess.Popen(["/bin/sleep", "30"]), chrome.pids, []
        self.addCleanup(helper.wait)
        self.addCleanup(helper.kill)  # our own child, standing in for a helper of the run

        def spy(pids):
            seen.append(sorted(pids))
            helper.kill()  # it ends with the browser
            helper.wait()
            return []

        with mock.patch.object(chrome, "pids", lambda: found() + [helper.pid]), \
                mock.patch.object(driver, "outside_loopback", spy):
            chrome.close()
        self.assertEqual(seen, [sorted([main, helper.pid])])

    def test_a_helper_that_exits_early_is_still_a_pid_of_the_run(self):
        # C2-09: the run's processes are listed at each look of the owner watch, not only at close(), so the log
        # checks at the suite's end still match a helper that ended before.
        chrome = self.start()
        helper = subprocess.Popen(["/bin/sh", "-c", "read line", "sh", chrome.profile[len("/private"):] + "/Crashpad"],
                                  stdin=subprocess.PIPE)  # named as the crash handler is: pids() finds it
        self.addCleanup(helper.wait)
        self.addCleanup(helper.kill)
        deadline = time.monotonic() + 5
        while helper.pid not in driver.RUN_PIDS and time.monotonic() < deadline:
            time.sleep(0.1)
        helper.stdin.close()
        helper.wait(10)
        chrome.close()  # its own list no longer has the helper
        self.assertIn(helper.pid, driver.RUN_PIDS)

    def test_a_run_writes_only_in_its_own_folders(self):
        # C2-01: the driver's run folder and the run root that holds the test HOME, never /tmp itself.
        calls, spawn = [], os.posix_spawn

        def record(path, argv, env, **kwargs):
            calls.append(argv[2])
            return spawn(path, argv, env, **kwargs)

        root = temp_folder(self)
        with mock.patch.object(driver.os, "posix_spawn", record):
            chrome = self.start(home=os.path.join(root, "home"))
        self.assertIn('(deny file-write*)\n(allow file-write* %s)\n' % " ".join(
            '(subpath "%s")' % p for p in sorted([os.path.realpath(chrome.folder), os.path.realpath(root)])), calls[0])
        chrome.close()
        with mock.patch.object(driver.os, "posix_spawn", calls.append):
            with self.assertRaisesRegex(driver.DriverError, "test HOME must be in a folder of its run under /tmp"):
                self.start(home=temp_folder(self))  # its folder would be /tmp itself
        self.assertEqual(len(calls), 1)

    # Round 4 (2026-11-22): the Checkers' C1R3 and C2R3 findings and the lead's rulings.

    def test_a_named_unix_socket_of_the_run_outside_its_folders_fails_the_run(self):
        # C2R3-02: listed with lsof -U for every PID of the run while it runs, as the internet sockets are.
        chrome = self.start()
        pid, seen = chrome.pid, []
        with mock.patch.object(driver, "unix_sockets_outside",
                               lambda pids, folders: seen.append((pids, folders)) or ["/private/var/run/x.sock"]):
            with self.assertRaisesRegex(driver.DriverError, r"STOP \(rule 7\): a process of the run had a named unix "
                                        r"socket outside the run's folders: /private/var/run/x\.sock"):
                chrome.close()
        self.assertIn(pid, seen[0][0])
        self.assertEqual(seen[0][1], chrome.writable)

    def test_the_browser_and_the_guard_get_a_run_folder_as_their_instance_folder(self):
        # C2R3-02: a debug larsal-bridge under them never falls back to the owner's per-user temp folder.
        folder = temp_folder(self)
        before, said = os.path.join(folder, "front"), os.path.join(folder, "said")
        with open(before, "w") as f:
            f.write("0")
        fake = fake_guard(self, before, before)
        with open(fake, "a") as f:  # the stand-in guard also says where its LARSAL_TEST_INSTANCE_DIR points
            f.write('echo "$LARSAL_TEST_INSTANCE_DIR" > "%s"\n' % said)
        calls, spawn = [], os.posix_spawn

        def record(path, argv, env, **kwargs):
            calls.append(dict(env))
            return spawn(path, argv, env, **kwargs)

        with mock.patch.object(driver, "guard_binary", lambda: fake), mock.patch.object(driver.os, "posix_spawn", record):
            chrome = self.start()
        run = chrome.folder
        self.assertEqual(calls[0]["LARSAL_TEST_INSTANCE_DIR"], os.path.realpath(run))
        chrome.close()
        with open(said) as f:
            self.assertEqual(f.read().strip(), run)

    def test_every_start_keeps_a_netlog_in_its_run_folder_unless_the_test_names_one(self):
        # C1R3-03, C2R3-05: so a failed start or page load can show its socket connects.
        calls, spawn = [], os.posix_spawn

        def record(path, argv, env, **kwargs):
            calls.append(list(argv))
            return spawn(path, argv, env, **kwargs)

        root = temp_folder(self)
        with mock.patch.object(driver.os, "posix_spawn", record):
            first = self.start()
            second = self.start(home=os.path.join(root, "home"), args=["--log-net-log=" + os.path.join(root, "n.json")])
        self.assertEqual([[a for a in argv if "net-log" in a] for argv in calls],
                         [["--log-net-log=" + os.path.join(first.folder, "net.json")],
                          ["--log-net-log=" + os.path.join(root, "n.json")]])
        self.assertEqual((first.netlog, second.netlog),
                         (os.path.join(first.folder, "net.json"), os.path.join(root, "n.json")))
        first.close()
        second.close()

    def test_a_failed_page_load_keeps_the_starts_socket_connects_and_names_them(self):
        # C1R3-03, C2R3-05: the connect events (addresses, ports, errors) go next to the error, in a folder under
        # /tmp the run does not remove, written again from the whole NetLog at close().
        chrome = self.start()
        drop_kept(self, chrome)
        with open(chrome.netlog, "w") as f:  # as the browser writes it while it runs
            f.write(NETLOG)
        page = driver.Session(chrome, "S", "T")
        for name, send in (("error page", lambda *a, **k: {"errorText": "net::ERR_CONNECTION_REFUSED"}),
                           ("no load event", lambda *a, **k: {})):
            with mock.patch.object(page, "send", send), \
                    self.assertRaisesRegex(driver.DriverError, r"^https://site-a\.test/: .*\(socket connects of this "
                                           r"start: (/tmp/larsal-netlog-\w+/connects\.json)\)$", msg=name) as e:
                page.navigate("https://site-a.test/", timeout=0.2)
            path = re.search(r"start: (\S+)\)$", str(e.exception)).group(1)
            with open(path) as f:
                record = json.load(f)
            self.assertEqual((record["why"], record["browser_running"]), ("page load https://site-a.test/", True))
            self.assertEqual([c["params"] for c in record["connects"]], NETLOG_CONNECTS, name)
        self.assertEqual(len(chrome.kept), 2)
        with open(chrome.netlog, "a") as f:  # the browser stops: the list is closed and the file whole
            f.write('{"type": 2, "time": "5", "phase": 1, "source": {"id": 9}, "params": {"address": "[::1]:8443"}}]}\n')
        kept = [path for _, path in chrome.kept]
        chrome.close()
        for path in kept:
            with open(path) as f:
                record = json.load(f)
            self.assertFalse(record["browser_running"])
            self.assertEqual([c["params"] for c in record["connects"]], NETLOG_CONNECTS + [{"address": "[::1]:8443"}])

    def test_a_refused_page_load_asks_a_fresh_process_under_the_runs_own_sandbox(self):
        # Round 4: extension-1's second try failed on net::ERR_ACCESS_DENIED to the demo port, and fresh processes
        # under the same profile were refused too (r4/probes/tcp-many-1): the rule order refused that port. The
        # error says which it was: the probe runs under the run's own profile (the one the browser was started in)
        # against the demo port.
        port, spawned, spawn = tcp_listeners(self), [], os.posix_spawn
        record = lambda path, argv, env, **kwargs: spawned.append(list(argv)) or spawn(path, argv, env, **kwargs)
        with mock.patch.object(driver.os, "posix_spawn", record):
            chrome = self.start(sites=types.SimpleNamespace(port=port, spki=None))
        self.assertEqual(spawned[-1][:3], [driver.SANDBOX, "-p", chrome.sandbox])
        self.assertIn('(allow network-outbound (remote tcp "localhost:%d"))' % port, chrome.sandbox)
        drop_kept(self, chrome)
        page = driver.Session(chrome, "S", "T")
        before = set(driver.RUN_PIDS)
        for profile, words in ((chrome.sandbox, r"; a fresh process under this run's own sandbox profile, TCP to the "
                                                r"demo server on 127\.0\.0\.1:%d: connected \(socket" % port),
                               (driver.sandbox_profile(chrome.writable), r"; a fresh process under this run's own "
                                r"sandbox profile was refused TCP to the demo server on 127\.0\.0\.1:%d too: the run's "
                                r"profile refuses the demo port \(socket" % port)):  # the second refuses the port
            chrome.sandbox = profile
            refused = r"^https://site-a\.test/: net::ERR_ACCESS_DENIED" + words
            with mock.patch.object(page, "send", lambda *a, **k: {"errorText": "net::ERR_ACCESS_DENIED"}), \
                    self.assertRaisesRegex(driver.DriverError, refused):
                page.navigate("https://site-a.test/")
        self.assertEqual(len(driver.RUN_PIDS - before), 2)  # each probe is a process of the run

    def test_a_failed_start_keeps_its_socket_connects_and_names_them_in_the_error(self):
        calls, spawn = [], os.posix_spawn

        def record(path, argv, env, **kwargs):
            calls.append(list(argv))
            return spawn(path, argv, env, **kwargs)

        def command_line(pid):  # the start fails after the spawn: its NetLog is there, being written
            log = [a.split("=", 1)[1] for a in calls[-1] if a.startswith("--log-net-log=")][0]
            with open(log, "w") as f:
                f.write(NETLOG)
            return "/x/browser --headless=new"

        self.binary = fake_browser(self)
        with mock.patch.dict(os.environ, {driver.TEST_CHROME: self.binary}), \
                mock.patch.object(driver.os, "posix_spawn", record), mock.patch.object(driver, "command_line", command_line):
            with self.assertRaisesRegex(driver.DriverError, r"--use-mock-keychain is not on Chrome's command line: stop "
                                        r"and report \(socket connects of this start: /tmp/larsal-netlog-\w+/connects"
                                        r"\.json\)$") as e:
                driver.Chrome()
        drop_kept_in(self, e.exception)
        path = re.search(r"start: (\S+)\)$", str(e.exception)).group(1)
        with open(path) as f:
            record = json.load(f)
        self.assertEqual(record["why"], "the start: --use-mock-keychain is not on Chrome's command line: stop and report")
        self.assertEqual([c["params"] for c in record["connects"]], NETLOG_CONNECTS)
        self.assertFalse(record["browser_running"])  # written again at close(), once the browser had stopped

    def test_a_failed_start_whose_close_fails_too_still_names_its_socket_connects(self):
        # Round 4: when close() fails as well (a window guard that stopped early), its error is the one raised, and
        # it named no file, so the folder was left behind unnamed.
        calls, spawn, close = [], os.posix_spawn, driver.Chrome.close

        def record(path, argv, env, **kwargs):
            calls.append(list(argv))
            return spawn(path, argv, env, **kwargs)

        def command_line(pid):
            log = [a.split("=", 1)[1] for a in calls[-1] if a.startswith("--log-net-log=")][0]
            with open(log, "w") as f:
                f.write(NETLOG)
            return "/x/browser --headless=new"

        def failing_close(chrome):  # the real close, then the error a guard that stopped early gives
            close(chrome)
            raise driver.DriverError("rule 10: window guard: stopped early")

        self.binary = fake_browser(self)
        with mock.patch.dict(os.environ, {driver.TEST_CHROME: self.binary}), \
                mock.patch.object(driver.os, "posix_spawn", record), \
                mock.patch.object(driver, "command_line", command_line), \
                mock.patch.object(driver.Chrome, "close", failing_close):
            with self.assertRaisesRegex(driver.DriverError, r"^rule 10: window guard: stopped early \(socket connects "
                                        r"of this start: /tmp/larsal-netlog-\w+/connects\.json\)$") as e:
                driver.Chrome()
        drop_kept_in(self, e.exception)
        with open(re.search(r"start: (\S+)\)$", str(e.exception)).group(1)) as f:
            record = json.load(f)
        self.assertEqual(record["why"], "the start: --use-mock-keychain is not on Chrome's command line: stop and report")
        self.assertFalse(record["browser_running"])

    def test_connects_reads_a_whole_netlog_and_one_still_being_written(self):
        folder = temp_folder(self)
        whole, partial = os.path.join(folder, "whole.json"), os.path.join(folder, "partial.json")
        with open(partial, "w") as f:
            f.write(NETLOG + '{"type": 2, "time": "5", "pha')  # the line being written
        with open(whole, "w") as f:
            f.write(NETLOG.rstrip().rstrip(",") + "]}")
        for path in (whole, partial):
            found = driver.connects(path)
            self.assertEqual([(c["type"], c["source"], c["params"]) for c in found],
                             [("TCP_CONNECT", 8, NETLOG_CONNECTS[0]), ("TCP_CONNECT_ATTEMPT", 8, NETLOG_CONNECTS[1]),
                              ("TCP_CONNECT", 8, NETLOG_CONNECTS[2])], path)

    def test_only_the_listed_test_flags_may_be_added_to_a_start(self):
        # C2R3-06: one list, each flag with its reason; a flag that names a program or a command prefix for the
        # browser's helpers, or one the list does not hold, is refused before anything starts. The list holds every
        # flag a suite passes today (only the DNS error page test passes any).
        self.assertEqual(sorted(driver.TEST_FLAGS), ["--log-net-log", "--net-log-capture-mode"])
        self.assertEqual([f for f, reason in driver.TEST_FLAGS.items() if len(reason) < 20], [])
        driver.check_test_flags(["--log-net-log=/tmp/x/net.json", "--net-log-capture-mode=Everything"])
        self.binary = fake_browser(self)
        before, spawned, guards = set(driver.RUN_PIDS), [], []
        with mock.patch.dict(os.environ, {driver.TEST_CHROME: self.binary}), \
                mock.patch.object(driver.os, "posix_spawn", spawned.append), \
                mock.patch.object(driver, "guard_binary", lambda: guards.append(1) or "/usr/bin/false"):
            for flag in ("--browser-subprocess-path=/bin/sh", "--renderer-cmd-prefix=/bin/sh -c",
                         "--utility-cmd-prefix=/bin/sh", "--gpu-launcher=/bin/sh", "--unknown-flag",
                         "-browser-subprocess-path=/bin/sh", "https://site-a.test/"):
                with self.assertRaisesRegex(driver.DriverError, "refused before the start: .*not on the driver's list "
                                            "of test flags", msg=flag):
                    driver.Chrome(args=["--log-net-log=/tmp/x/net.json", flag])
        self.assertEqual((spawned, guards, driver.RUN_PIDS - before), ([], [], set()))  # nothing started

    def front_run(self, front):
        """A start with a stand-in guard that reports the PID `front(chrome)` writes as the frontmost app at the end;
        returns the browser's PID and close()'s error, if any."""
        folder = temp_folder(self)
        before, after = os.path.join(folder, "before"), os.path.join(folder, "after")
        other = max(driver.RUN_PIDS | {os.getpid()}) + 100000  # no PID of the run
        for path in (before, after):
            with open(path, "w") as f:
                f.write(str(other))
        with mock.patch.object(driver, "guard_binary", lambda: fake_guard(self, before, after)):
            chrome = self.start()
        pid = chrome.pid
        with open(after, "w") as f:
            f.write(str(front(chrome, other)))
        try:
            chrome.close()
        except driver.DriverError as e:
            return pid, other, e
        return pid, other, None

    def test_a_process_of_the_run_as_the_frontmost_app_fails_the_run(self):
        # C2R3-10: any PID pids() returned at any look; here the browser itself.
        pid, other, error = self.front_run(lambda chrome, other: chrome.pid)
        self.assertRegex(str(error), r"rule 10: a process of the run was the frontmost app: \[%d\]" % pid)

    def test_the_owners_own_switch_of_the_frontmost_app_is_noted_not_failed(self):
        # C2R3-10: the owner works on this Mac; a change between apps of no process of the run is noted.
        with mock.patch.object(driver, "FRONT_NOTES", []), mock.patch.object(sys, "stderr", io.StringIO()) as err:
            pid, other, error = self.front_run(lambda chrome, other: other + 1)
            self.assertIsNone(error)
            self.assertEqual(driver.FRONT_NOTES, [(other, other + 1)])
        self.assertIn("the owner's own switch; recorded, not a failure", err.getvalue())

    def test_a_run_root_made_elsewhere_is_refused_before_the_profile_is_built(self):
        # C1R3-06: nothing is written in it and nothing starts; once this process marks it, it is a run root.
        other = tempfile.mkdtemp(prefix="larsal-driver-test-", dir="/tmp")
        self.addCleanup(shutil.rmtree, other, True)
        self.binary = fake_browser(self)
        spawned, guards, profiles, profile = [], [], [], driver.sandbox_profile
        with mock.patch.dict(os.environ, {driver.TEST_CHROME: self.binary}), \
                mock.patch.object(driver.os, "posix_spawn", spawned.append), \
                mock.patch.object(driver, "guard_binary", lambda: guards.append(1) or "/usr/bin/false"), \
                mock.patch.object(driver, "sandbox_profile", lambda *a: profiles.append(a) or profile(*a)):
            with self.assertRaisesRegex(driver.DriverError, "was not made by this driver process"):
                driver.Chrome(home=os.path.join(other, "home"))
        self.assertEqual((spawned, guards, profiles, os.listdir(other)), ([], [], [], []))
        driver.mark_root(other)
        self.start(home=os.path.join(other, "home")).close()


class DemoServerTests(unittest.TestCase):
    def test_demo_server_serves_only_the_three_test_names(self):
        sites = driver.TestSites(temp_folder(self))
        self.addCleanup(sites.close)
        self.assertEqual(sites.server.server_address[0], "127.0.0.1")  # loopback only, never every interface
        context = ssl.create_default_context(cafile=sites.cert)
        context.check_hostname = False  # the client dials 127.0.0.1; the certificate itself is checked

        def get(host, path):
            connection = http.client.HTTPSConnection("127.0.0.1", sites.port, context=context, timeout=10)
            connection.request("GET", path, headers={"Host": "%s:%d" % (host, sites.port)})
            status = connection.getresponse().status
            connection.close()
            return status

        self.assertEqual(get("site-a.test", "/"), 200)
        self.assertEqual(get("site-b.test", "/frame.html"), 200)
        self.assertEqual(get("other.test", "/"), 404)
        self.assertEqual(get("..", "/"), 404)
        self.assertEqual(get("site-a.test", "/../site-b.test/frame.html"), 404)


class WorkerReady(unittest.TestCase):
    """F-476, LD-520 (4): Chrome.worker returns only once the worker answers a trivial evaluate."""

    class Fake:
        def __init__(self, answers):
            self.answers, self.calls = list(answers), []

        def eval(self, expression, timeout=30):
            self.calls.append((expression, timeout))
            answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]  # the last one stays
            if isinstance(answer, Exception):
                time.sleep(min(timeout, 0.05))  # no answer: Chrome's reply wait ran out
                raise answer
            return answer

    def test_worker_waits_for_a_trivial_evaluate_before_the_first_real_one(self):
        chrome = driver.Chrome.__new__(driver.Chrome)
        fake = self.Fake([driver.DriverError("Runtime.evaluate: no answer from Chrome"), 1])
        targets = {"targetInfos": [{"type": "service_worker", "url": "chrome-extension://%s/background.js" % ("a" * 32),
                                    "targetId": "T"}]}
        with mock.patch.object(chrome, "send", lambda *a, **k: targets, create=True), \
                mock.patch.object(chrome, "attach", lambda target: fake, create=True):
            self.assertIs(chrome.worker("a" * 32), fake)
        self.assertEqual([c[0] for c in fake.calls], ["1", "1"])  # the first try got no answer; the second did
        self.assertTrue(all(c[1] <= 5 for c in fake.calls))

    def test_a_worker_that_never_answers_fails_within_its_bound(self):
        start = time.monotonic()
        fake = self.Fake([driver.DriverError("no answer")])
        with self.assertRaisesRegex(driver.DriverError, "never answered a trivial evaluate"):
            driver.Chrome.answering(fake, ready=0.3, each=0.1)
        self.assertLess(time.monotonic() - start, 2)
        self.assertGreater(len(fake.calls), 1)


if __name__ == "__main__":
    unittest.main()
