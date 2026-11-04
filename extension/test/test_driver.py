"""Tests of the headless Chrome driver (story E7-S7b).

Run: python3 -I extension/test/test_driver.py
Needs /Applications/Google Chrome.app, /usr/bin/openssl and Xcode's swiftc. No window,
no network beyond 127.0.0.1, nothing outside /tmp (AGENTS.md rules 7, 10, 11).
"""

import http.client
import json
import os
import shutil
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import driver  # noqa: E402

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


RUN = {}


def setUpModule():
    RUN["start"] = time.time()


def tearDownModule():
    # LD-276: after the suite run, macOS's own log shows no keychain write by a PID of the run.
    found = driver.keychain_commits(driver.keychain_log(RUN["start"], time.time()), driver.RUN_PIDS | {os.getpid()})
    if found:
        raise driver.OwnerFilesChanged("STOP (LD-276): a process of this run wrote a keychain: " + "; ".join(found))


def temp_folder(case):
    folder = tempfile.mkdtemp(prefix="larsal-driver-test-", dir="/tmp")
    case.addCleanup(shutil.rmtree, folder, True)
    return folder


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
        page = self.chrome.open()
        for url in ("https://localhost:%d/" % self.sites.port, "https://127.0.0.1:%d/" % self.sites.port):
            with self.assertRaisesRegex(driver.DriverError, "ERR_NAME_NOT_RESOLVED"):
                page.navigate(url)

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

    def test_echo_host_answers_connect_native_from_the_int_01_8_folder(self):
        manifest = driver.install_echo_host(self.chrome.home, self.extension)
        self.assertEqual(manifest, os.path.join(
            self.chrome.home, "Library/Application Support/Google/Chrome/NativeMessagingHosts/app.larsal.test.echo.json"))
        answer = self.chrome.worker(self.extension).eval(CONNECT_ECHO)
        self.assertEqual(answer, {"echo": {"hello": "echo"}, "caller": ["chrome-extension://%s/" % self.extension]})

    def test_live_main_chrome_runs_with_the_mock_keychain_flag(self):
        self.assertIn("--use-mock-keychain", driver.command_line(self.chrome.pid).split())
        self.assertIn(self.chrome.pid, driver.RUN_PIDS)  # the after-run keychain log check looks for it

    def test_no_window_no_dock_icon_and_focus_never_moves_so_far(self):
        self.assertEqual(self.chrome.hits, [])
        self.assertIsNone(self.chrome.guard.poll(), "the window guard must still run")
        apps = subprocess.run(["/usr/bin/lsappinfo", "list"], capture_output=True, text=True).stdout
        self.assertIn('pid = %d type="BackgroundOnly"' % self.chrome.pid, apps)  # no Dock icon, no menu bar


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
        self.assertEqual(chrome.front_after, chrome.front_before)
        self.assertEqual(driver.owner_times(), before)
        self.assertLessEqual(set(pids) | {chrome.guard.pid}, driver.RUN_PIDS)

    def test_a_chrome_whose_command_line_lacks_the_mock_keychain_flag_is_stopped(self):
        # Chrome itself always gets the flag; only the reading of its command line is faked.
        before, made = set(driver.RUN_PIDS), []
        self.addCleanup(lambda: [chrome.close() for chrome in made])  # only when the driver lets Chrome run
        with mock.patch.object(driver, "command_line", lambda pid: driver.CHROME + " --headless=new"):
            with self.assertRaisesRegex(driver.DriverError, "--use-mock-keychain is not on Chrome's command line"):
                made.append(driver.Chrome())
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
            with self.assertRaisesRegex(driver.DriverError, "window guard: stopped early"):
                made.append(driver.Chrome())

    def test_a_change_of_the_frontmost_app_fails_the_run(self):
        chrome = driver.Chrome()
        self.addCleanup(chrome.close)
        chrome.front_before = -1  # as if another app was in front at the start
        with self.assertRaisesRegex(driver.DriverError, "frontmost app changed from -1"):
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
            "--user-data-dir=" + profile, "--use-mock-keychain", "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
            "--disable-updater-scheduler", "--disable-features=MacAppCodeSignClone", "--disable-sync",
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
        log = os.path.join(temp_folder(self), "net.json")
        chrome = driver.Chrome(args=["--log-net-log=" + log, "--net-log-capture-mode=Everything"])
        self.addCleanup(chrome.close)
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


if __name__ == "__main__":
    unittest.main()
