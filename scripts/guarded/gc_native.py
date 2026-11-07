"""The native step, driver N1b with its roots as parameters: one outer sandbox-exec per attempt, caps, process samples, kernel rows, T listing and T cleanup, and the gates.
Exit 0 from an attempt only if its step exit is 0 and every gate holds; each failed gate is a stated reason in runs/<name>/gates.json.
Signals go only to the process group it started, through its Popen handle, with the leader unreaped."""
import ctypes, datetime, json, os, plistlib, re, shutil, signal, stat, subprocess, threading, time
from pathlib import Path
import gc_lib as L
import gc_pins, gc_profiles
from gc_profiles import GRANTED, deny_lines

PY = L.PY
ATTEMPT_CAP = 1800
STALL = {'A': 900, 'B': 600}
UUID = r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'
LISTS = [('', re.compile('(?:actool-sprite-atlas-scratch-)?' + UUID + r'|ibtoold-[0-9]+|Untitled-[A-Za-z0-9]{8}\.uicatalog(?:-journal)?', re.A))]
INTEREST = re.compile(r'(?:^|/)(?:xctest|Larsal|larsal-bridge|testmanagerd|DTServiceHub|XCTRunner[^/]*|xctest[^/]*|open|app09-[0-9a-f]+|launchservicesd)$')
TOOLS = 'xcresulttool swift-format swift swiftlint xcodebuild SWBBuildService XCBBuildService swift-frontend swiftc swift-driver swift-plugin-server swift-autolink-extract clang clang++ cc c++ ld ld-classic libtool ar ranlib lipo actool ibtool ibtoold AssetCatalogAgent-AssetRuntime AssetCatalogAgent IBAgent-macOS codesign codesign_allocate cp mkdir rm ln sh bash env cat python3 Python xcrun xcode-select cargo rustc rustdoc rustup uniffi-bindgen-swift xctest Larsal larsal larsal-bridge open plutil dsymutil strip ditto touch sed awk grep date mktemp tr cut app09 mv tar find sort head tail uname sw_vers git xcodebuild-launcher lldb debugserver DTServiceHub testmanagerd'.split()
R = S = RUNS = OUT = T = OWNER = TOOL_DIR = NSIRD = None
SWIFT_TESTS = APP09_TESTS = None
TOOLCHAIN = None
WITHHELD = {}


def configure(root, tool, t, owner, toolchain, expected, withheld=None):
    """Everything a run names: the root, its source, T, the owner's home, the pinned totals, and the needs rows whose grant is withheld."""
    global R, S, RUNS, OUT, T, OWNER, TOOL_DIR, NSIRD, TOOLCHAIN, SWIFT_TESTS, APP09_TESTS, WITHHELD
    WITHHELD = withheld or {}
    R, S, RUNS, OUT = Path(root), Path(root) / 's', Path(root) / 'runs', Path(root) / 'lane-out'
    T, OWNER, TOOL_DIR, TOOLCHAIN = t, owner, Path(tool), toolchain
    SWIFT_TESTS, APP09_TESTS = expected
    assert len(str(S)) <= 37, 'W-15: the source root must stay at 37 characters or fewer: ' + str(S)
    NSIRD = re.compile('^' + T + r'/TemporaryItems/NSIRD_(?:xcodebuild|SWBBuildService|ibtool|xctest|swiftlint|Larsal)_[A-Za-z0-9]{6}(?:$|/)', re.A)


def load(p): return L.load(p)
def save(p, x): L.save(p, x)


# ---- Needs: lines added on the evidence of a denial row. Each carries its row. Empty until a row earns one.
def needs():
    return gc_profiles.native_needs(TOOL_DIR, str(R), T, WITHHELD)


def extra_lists():
    return [(n['t_folder'], re.compile(n['t_name'], re.A)) for n in needs() if n.get('t_name')]


# ---- T: filtered names and exact-name stats. FIFOs are never opened and links never followed.
def t_listing():
    rows = []
    for folder, pattern in LISTS + extra_lists():
        path = T + ('/' + folder if folder else '')
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        try:
            for name in sorted(os.listdir(fd)):
                if pattern.fullmatch(name):
                    try:
                        s = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    rows.append(dict(path=path + '/' + name, uid=s.st_uid, kind=stat.S_IFMT(s.st_mode), birth=s.st_birthtime, inode=s.st_ino))
        finally:
            os.close(fd)
    return rows


def deny_tail(rows):
    out = ''
    for p in sorted({r['path'] for r in rows}):
        assert p.isascii() and p.startswith('/')
        out += deny_lines('(subpath ' + json.dumps(p) + ')')
    assert '(allow' not in out
    return out


def remove_tree(fd, name, uid, removed, left, rel):
    # Deepest first. lstat, unlink and rmdir only; a directory is opened by O_NOFOLLOW to read names and nothing else is opened.
    try:
        s = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if s.st_uid != uid:
            left.append(dict(path=rel, issue='other uid'))
            return
        if stat.S_ISDIR(s.st_mode):
            d = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                assert (os.fstat(d).st_dev, os.fstat(d).st_ino) == (s.st_dev, s.st_ino), 'swapped during cleanup'
                for child in sorted(os.listdir(d)):
                    remove_tree(d, child, uid, removed, left, rel + '/' + child)
            finally:
                os.close(d)
            os.rmdir(name, dir_fd=fd)
        else:
            os.unlink(name, dir_fd=fd)
        removed.append(rel)
    except (OSError, AssertionError) as e:
        left.append(dict(path=rel, issue=repr(e)))


def t_cleanup(before, window, created, tree_pids):
    # Removed only if: absent before, own UID, born in the attempt window, named by an allow row from a process in this sandbox.
    known = {r['path'].lower() for r in before}
    uid = os.getuid()
    removed, left = [], []
    for row in t_listing():
        p = row['path']
        if p.lower() in known:
            continue
        reason = None
        if row['uid'] != uid:
            reason = 'other uid'
        elif not window[0] - 1 <= row['birth'] <= window[1] + 1:
            reason = 'birth time outside the attempt window'
        elif p not in created:
            reason = 'no allow row from a process in this sandbox names it'
        if reason:
            left.append(dict(path=p, issue=reason))
            continue
        folder, name = os.path.split(p)
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            s = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if s.st_ino != row['inode'] or s.st_uid != uid:
                left.append(dict(path=p, issue='changed after the listing'))
            elif stat.S_ISDIR(s.st_mode) and re.fullmatch(r'ibtoold-[0-9]+', name, re.A):
                remove_tree(fd, name, uid, removed, left, p)
            elif stat.S_ISDIR(s.st_mode):
                if os.listdir(p):  # A plain name with contents: listed and left. No recursion outside the ibtoold tree.
                    left.append(dict(path=p, issue='not empty'))
                else:
                    os.rmdir(name, dir_fd=fd)
                    removed.append(p)
            else:
                os.unlink(name, dir_fd=fd)
                removed.append(p)
        except OSError as e:
            left.append(dict(path=p, issue=repr(e)))
        finally:
            os.close(fd)
    # T/TemporaryItems cannot be listed, so its NSIRD names are found only through allow rows, by exact name, deepest first.
    for p in sorted((c for c in created if NSIRD.match(c)), key=len, reverse=True):
        try:
            s = os.lstat(p)
        except FileNotFoundError:
            continue
        except OSError as e:
            left.append(dict(path=p, issue=repr(e)))
            continue
        if s.st_uid != uid or not window[0] - 1 <= s.st_birthtime <= window[1] + 1:
            left.append(dict(path=p, issue='other uid or born outside the attempt window'))
            continue
        try:
            (os.rmdir if stat.S_ISDIR(s.st_mode) else os.unlink)(p)
            removed.append(p)
        except OSError as e:
            left.append(dict(path=p, issue=repr(e)))
    return dict(removed=removed, left=left)


# ---- The guarded run's environment: fixture shape, private paths, one manifest route.
def environment():
    x = '/Applications/Xcode.app/Contents/Developer'
    tc = x + '/Toolchains/XcodeDefault.xctoolchain/usr/bin'
    rust = OWNER + '/.rustup/toolchains/' + TOOLCHAIN + '/bin'
    r = str(R)
    return dict(
        PATH=':'.join([rust, tc, x + '/usr/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
        HOME=r + '/home', CFFIXED_USER_HOME=r + '/home', CARGO_HOME=r + '/home/.cargo',
        TMPDIR=r + '/tmp/', TMP=r + '/tmp/', TEMP=r + '/tmp/', XDG_CACHE_HOME=r + '/cache',
        CARGO_TARGET_DIR=str(S / 'target'), CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='4',
        RUSTUP_HOME=OWNER + '/.rustup', RUSTUP_AUTO_INSTALL='0', RUSTUP_TOOLCHAIN=TOOLCHAIN,
        RUSTC=rust + '/rustc', RUSTDOC=rust + '/rustdoc',
        DEVELOPER_DIR=x, SDKROOT=x + '/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk', MACOSX_DEPLOYMENT_TARGET='14.0',
        CC=tc + '/clang', CXX=tc + '/clang++', AR=tc + '/ar', RANLIB=tc + '/ranlib', CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=tc + '/clang',
        CLANG_MODULE_CACHE_PATH=r + '/modules/clang', SWIFT_MODULECACHE_PATH=r + '/modules/swift', SWIFTPM_MODULECACHE_OVERRIDE=r + '/modules/swiftpm',
        SWIFT_EXEC_MANIFEST=r + '/bin/swiftc',
        SSH_AUTH_SOCK=r + '/no-owner-ssh.sock',
        LARSAL_TEST_INSTANCE_DIR=r + '/instance', LARSAL_TEST_HIDDEN='1',
        TEST_RUNNER_HOME=r + '/home', TEST_RUNNER_CFFIXED_USER_HOME=r + '/home', TEST_RUNNER_TMPDIR=r + '/tmp/',
        TEST_RUNNER_LARSAL_TEST_INSTANCE_DIR=r + '/instance', TEST_RUNNER_LARSAL_TEST_HIDDEN='1', TEST_RUNNER_SSH_AUTH_SOCK=r + "/no-owner-ssh.sock", TEST_RUNNER_DYLD_INSERT_LIBRARIES="/Applications/Xcode.app/Contents/Developer/usr/lib/libMainThreadChecker.dylib:/usr/lib/libRPAC.dylib:" + r + "/bin/guard-board.dylib", TEST_RUNNER_LARSAL_GUARD_LOG=r + "/lane-out/guard/general-board.log", LARSAL_GUARD_LOG=r + "/lane-out/guard/general-board.log",
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', LC_ALL='C',
    )


# ---- Process samples. Observes only.
LIB = L.LIB
LIB.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
LIB.proc_listpgrppids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
SB = ctypes.CDLL('/usr/lib/system/libsystem_sandbox.dylib')
SB.sandbox_check.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
LIBC = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)


def children(pid):
    ids = (ctypes.c_int * 1024)()
    LIB.proc_listchildpids(pid, ids, ctypes.sizeof(ids))
    return [i for i in ids if i > 0]


image = L.image


def sandboxed(pid):
    return SB.sandbox_check(pid, None, 0)  # 1 when the process runs in a sandbox; 0 when not. Read only.


ENV_KEEP = re.compile(r'LARSAL_.*|HOME|TMPDIR|CFFIXED_USER_HOME|SSH_AUTH_SOCK|XCTest.*|XCInject.*|XPC_SERVICE_NAME|XPC_FLAGS|DYLD_.*|__XPC_.*|OS_ACTIVITY_DT_MODE|NSUnbufferedIO|__CFBundleIdentifier|TEST_RUNNER_.*')
def procargs(pid):
    """KERN_PROCARGS2, read only. Argv and allow-listed variables, kept only when the run's root is named: another agent's process is never recorded."""
    mib = (ctypes.c_int * 3)(1, 49, pid)
    size = ctypes.c_size_t(1 << 20)
    buf = ctypes.create_string_buffer(size.value)
    if LIBC.sysctl(mib, 3, buf, ctypes.byref(size), None, ctypes.c_size_t(0)) != 0:
        return dict(error=ctypes.get_errno())
    raw = buf.raw[:size.value]
    if str(R).encode() not in raw:
        return None
    argc = int.from_bytes(raw[:4], 'little')
    parts = [p.decode('utf-8', 'replace') for p in raw[4:].split(b'\0') if p]
    return dict(exec_path=parts[0], argv=parts[1:argc + 1], env={k: v for k, _, v in (e.partition('=') for e in parts[argc + 1:]) if ENV_KEEP.fullmatch(k)})


class Sampler(threading.Thread):
    daemon = True

    def __init__(self, root_pid, d, watch_windows):
        super().__init__()
        self.root, self.d, self.watch_windows = root_pid, d, watch_windows
        self.stop_flag = threading.Event()
        self.tree = {}    # pid -> first row, descendants by parent link
        self.other = {}   # pid -> row, interest images outside the tree
        self.args = {}    # pid -> its first read
        self.later_args = []  # What an exec'd pid held at each later image: an exec hides no read from gate_env.
        self.window_rows = []
        self.window_samples = 0
        self.window_seen = threading.Event()

    def note(self, pid, parent, in_tree, t0):
        """A pid's row follows what it became: its first image, each change after it in later_images, how many samples read an image, and a later start time if the pid was reused."""
        table = self.tree if in_tree else self.other
        path = image(pid)
        born = L.start_time(pid)
        row = table.get(pid)
        seconds = round(time.monotonic() - t0, 2)
        changed = row is None or path != (row.get('later_images') or [row['path']])[-1]
        if row is None:
            row = table[pid] = dict(pid=pid, parent=parent, path=path, started=born, samples=0, sandbox_check=sandboxed(pid), seconds=seconds, in_tree=in_tree)
        elif changed:
            row.setdefault('later_images', []).append(path)
        if born and born != row['started'] and born not in row.get('later_starts', []):
            row.setdefault('later_starts', []).append(born)
        row['samples'] += bool(path)
        if changed and path and INTEREST.search(path):
            got = procargs(pid)
            if got is not None:
                got.update(pid=pid, parent=parent, sandbox_check=row['sandbox_check'], seconds=seconds, path=path)
                if pid in self.args:
                    self.later_args.append(got)
                else:
                    self.args[pid] = got

    def ps(self, t0):
        r = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,comm='], env=dict(PATH='/usr/bin:/bin', HOME=str(R / 'home')), capture_output=True, timeout=30)
        uid = str(os.getuid())
        for line in r.stdout.decode('utf-8', 'replace').splitlines():
            parts = line.split(None, 4)
            if len(parts) == 5 and parts[3] == uid and INTEREST.search(parts[4]):
                pid, ppid = int(parts[0]), int(parts[1])
                if pid not in self.tree and pid not in self.other:
                    # A child of a tree process is in the tree: this list reached it before the walk did. The start time keeps a reused parent pid out.
                    parent, born = self.tree.get(ppid), L.start_time(ppid)
                    self.note(pid, ppid, bool(parent and born and parent.get('started') == born), t0)
                    if pid in self.other:
                        self.other[pid].update(ppid=ppid, pgid=int(parts[2]), comm=parts[4])

    def windows(self):
        mine = {p for p in list(self.tree) + [p for p, a in self.args.items()]}
        if not mine:
            return
        r = subprocess.run([PY, '-B', '-I', str(L.sealed(TOOL_DIR / 'windows.py'))] + [str(p) for p in sorted(mine)], env=dict(PATH='/usr/bin:/bin', HOME=str(R / 'home'), TMPDIR=str(R / 'tmp')), capture_output=True, timeout=20)
        row = json.loads(r.stdout or b'null')
        if not isinstance(row, list):  # A watcher that sees nothing is not a clean sample: the receipt shows it.
            raise RuntimeError('window list unavailable: %r' % (row,))
        self.window_samples += 1
        if row:
            self.window_rows.append(dict(at=time.time(), rows=row, stderr=r.stderr.decode('utf-8', 'replace')[:200]))
            if isinstance(row, list) and any(w.get('onscreen') for w in row):
                self.window_seen.set()

    def run(self):
        t0 = time.monotonic()
        last_ps = last_win = 0
        while not self.stop_flag.is_set():
            try:
                seen = {self.root}
                queue = [self.root]
                self.note(self.root, os.getpid(), True, t0)
                while queue:
                    p = queue.pop()
                    for c in children(p):
                        if c not in seen:
                            seen.add(c)
                            queue.append(c)
                            self.note(c, p, True, t0)
                now = time.monotonic()
                if now - last_ps > 1.5:
                    last_ps = now
                    self.ps(t0)
                if self.watch_windows and now - last_win > 3:
                    last_win = now
                    self.windows()
            except Exception as e:  # An observer never stops the run. Its error stays in the receipt.
                self.__dict__.setdefault('errors', []).append(repr(e))
            time.sleep(0.1)


# ---- Kernel rows.
ROW = re.compile(r'Sandbox: (?:(\d+) duplicate reports? for )?([^()\n]+?)(?:\((\d+)\))? (allow|deny)(?:\(\d+\))? (\S+)(?: (.*))?', re.S)
def query_log(d, started, ended, names, pids):
    lo = datetime.datetime.fromtimestamp(int(started) - 2).strftime('%Y-%m-%d %H:%M:%S')
    hi = datetime.datetime.fromtimestamp(int(ended) + 3).strftime('%Y-%m-%d %H:%M:%S')
    argv = ['/usr/bin/log', 'show', '--style', 'ndjson', '--start', lo, '--end', hi, '--predicate', '(processIdentifier == 0) AND (eventMessage BEGINSWITH "Sandbox: ")']
    r = subprocess.run(argv, env=dict(PATH='/usr/bin:/bin', HOME=str(R / 'home'), TMPDIR=str(R / 'tmp'), LC_ALL='C'), capture_output=True, timeout=max(5, L.time_left(240)))
    kept, other, sensitive = [], {}, []
    for line in r.stdout.decode('utf-8', 'replace').splitlines():
        try:
            m = json.loads(line).get('eventMessage', '')
        except ValueError:
            continue
        g = ROW.fullmatch(m.strip())
        if not g:
            continue
        name, pid = g[2], int(g[3]) if g[3] else None
        if g[4] == 'allow' and g[5] == 'mach-lookup' and (g[6] or '').strip() in SENSITIVE:
            sensitive.append(dict(process=name, pid=pid, target=g[6].strip(), count=int(g[1]) if g[1] else 1, in_tree=pid in pids))
        if name in names or pid in pids or re.fullmatch(r'app09-[0-9a-f]+|[a-z0-9_]+-[0-9a-f]{16}', name):
            kept.append(dict(process=name, pid=pid, verdict=g[4], operation=g[5], target=(g[6] or '').strip(), count=int(g[1]) if g[1] else 1, in_tree=pid in pids, raw=m[:600]))
        else:
            other[name] = other.get(name, 0) + 1  # Other programs on this Mac: name and count only, no row kept.
    (d / 'kernel-rows.ndjson').write_text(''.join(json.dumps(k) + '\n' for k in kept))
    save(d / 'kernel-other-process-names.json', other)
    tally = {}
    for k in kept:
        if k['verdict'] == 'deny':
            key = (k['process'], k['operation'], re.sub(r'\b' + UUID + r'\b', '<UUID>', k['target']), k['in_tree'])
            tally[key] = tally.get(key, 0) + k['count']
    rows = [dict(process=a, operation=b, target=c, pid_seen_in_tree=e, count=n) for (a, b, c, e), n in sorted(tally.items(), key=str)]
    save(d / 'deny-rows.json', rows)
    # The per-process, counted list a reader wants first.
    with (d / 'deny-rows.txt').open('x') as f:
        for x in rows:
            f.write('%6d %-32s %-22s %s%s\n' % (x['count'], x['process'], x['operation'], x['target'], '' if x['pid_seen_in_tree'] else '   [pid not sampled]'))
    save(d / 'sensitive-rows.json', sensitive)
    created = {k['target'] for k in kept if k['verdict'] == 'allow' and k['operation'] == 'file-write-create' and k['in_tree']}
    named = {k['target'] for k in kept if k['verdict'] == 'allow' and k['operation'] == 'file-write-create'}
    return dict(argv=argv, exit=r.returncode, stderr=r.stderr.decode('utf-8', 'replace')[:400], kept=len(kept), deny_keys=len(rows)), created, named, sensitive


# ---- Gates. Pure functions over evidence, each returning failures as stated reasons, so a control can break one condition at a time.
SENSITIVE = {
    'com.apple.pasteboard.1': {'xctest'},
    'com.apple.windowserver.active': {'xctest', 'Larsal'},
    'com.apple.coreservices.launchservicesd': {'Larsal'},
    'com.apple.lsd.mapdb': {'xcodebuild', 'xctest'},
}
gate_guard = L.gate_guard
VAR_TMP = '/private/var/tmp'
XCTEST_IMAGE = L.XCODE + '/Platforms/MacOSX.platform/Developer/Library/Xcode/Agents/xctest'
TESTMANAGERD = '/usr/libexec/testmanagerd'
CLOCK_SLACK = 2  # Seconds. A report's launch time and the kernel's start time are one clock read two ways; a pid is not reused inside this.
LANE_TREES = []  # Each attempt's tree and when it was read: a report can land after its own attempt's read.


def gate_sensitive(rows):
    bad = {}
    for r in rows:
        if r['process'] not in SENSITIVE.get(r['target'], ()):
            bad[(r['process'], r['target'])] = bad.get((r['process'], r['target']), 0) + r.get('count', 1)
    return ['sensitive grant %s used by %s (%d rows), allowed only for %s' % (t, p, n, sorted(SENSITIVE[t])) for (p, t), n in sorted(bad.items())]


def images_of(row):
    """Every image a row read, in order, without the reads after the pid was gone."""
    return [p for p in [row.get('path')] + row.get('later_images', []) if p]


def forked_once(row, tree):
    """One sample read an image, and it was the parent's: the pid may have been between fork and exec, so what it became was never seen. A row with no count (kept evidence) is not this."""
    return row.get('samples') == 1 and images_of(row)[0] in images_of(tree.get(row['parent']) or {})


def xctest_pids(tree):
    """The pids that became xctest, by the last image read. A fork of xctest read once may have become anything, so no guard line is asked of it."""
    return [q for q, r in tree.items() if os.path.basename((images_of(r) or [''])[-1]) == 'xctest' and not forked_once(r, tree)]


def gate_identity(rows, tree):
    """A signing identifier can be self-chosen. A sampled process using a sensitive grant as xctest or Larsal must be that image, in every sample. The kernel names a fork by its parent until exec, so one first image is not read: its parent's, under a basename other than the kernel row's name, with a later image read or read only once. What that leaves unseen: README, limit 28. A process the 0.1 s sampler missed is not covered."""
    fails = []
    want = dict(xctest=lambda p: p == XCTEST_IMAGE, Larsal=lambda p: p.startswith(str(S) + '/target/xcode/'))
    for x in rows:
        row = tree.get(x['pid']) or {}
        seen = images_of(row)
        if x['process'] not in want or not seen:
            continue
        if os.path.basename(seen[0]) != x['process'] and (forked_once(row, tree) or (len(seen) > 1 and seen[0] in images_of(tree.get(row['parent']) or {}))):
            seen = seen[1:]
        fails += ['sensitive grant %s used by pid %s named %s from another image: %s' % (x['target'], x['pid'], x['process'], p) for p in seen if not want[x['process']](p)]
    return sorted(set(fails))


def same_process(outside, inside):
    """Two rows of one pid are one process when the kernel's start time agrees. A row with no start time (kept evidence, or a pid gone before the read) falls back on the parent: a pid reused under the tree row's parent is a child of the tree anyway."""
    if outside.get('started') and inside.get('started'):
        return outside['started'] == inside['started']
    return outside.get('parent') == inside.get('parent')


def gate_outside(other, args, root, tree):
    """N1b read these by eye. A process outside the sandbox tree whose image sits under this root, or whose arguments or environment name it, is a containment failure. A pid the tree also read is not outside, if it is the same process. testmanagerd is the one known. The rest are listed, as other agents' builds show there."""
    fails = []
    for pid, row in other.items():
        image = row.get('path') or ''
        if pid in tree and same_process(row, tree[pid]):
            continue
        if image != TESTMANAGERD and (image.startswith(root + '/') or 'argv' in args.get(pid, {})):
            fails.append('a process outside the sandbox tree belongs to this run: pid %s %s' % (pid, image))
    return fails


def gate_xctestrun(products):
    """The test plan xcodebuild is about to run must be the reviewed one: one app test bundle, hosted by the real xctest, no UI test bundle under any name."""
    plans = sorted(Path(products).glob('*.xctestrun'))
    if len(plans) != 1:
        return ['a test bundle needs review: wanted one test plan, found %d' % len(plans)]
    try:
        plan = plistlib.loads(L.read_regular(plans[0]))
    except (OSError, ValueError, plistlib.InvalidFileException) as e:
        return ['a test bundle needs review: the test plan cannot be read: %r' % e]
    bundles = sorted(k for k in plan if not k.startswith('__'))
    if bundles != ['LarsalTests']:
        return ['a test bundle needs review: the test plan runs %s, the reviewed plan runs only LarsalTests' % bundles]
    row = plan['LarsalTests']
    fails = []
    if row.get('IsUITestBundle') or row.get('IsXCTRunnerHostedTestBundle') or row.get('UITargetAppPath'):
        fails.append('a test bundle needs review: LarsalTests is now a UI test bundle')
    if not str(row.get('TestHostPath', '')).endswith('/Agents/xctest'):
        fails.append('a test bundle needs review: LarsalTests is hosted by %s' % row.get('TestHostPath'))
    return fails


def gate_env(args, xctest_expected):
    """Every sampled Larsal and xctest ran hidden, with a private absent agent socket; xctest kept the main thread checker and the guard."""
    fails = []
    if xctest_expected and not any(os.path.basename(a.get('path') or '') == 'xctest' and 'env' in a for a in args):
        fails.append('the environment of xctest was never read')
    for a in args:
        base = os.path.basename(a.get('path') or '')
        if base not in ('Larsal', 'xctest') or 'env' not in a:
            continue
        env = a['env']
        if env.get('LARSAL_TEST_HIDDEN') != '1':
            fails.append('%s pid %s ran without LARSAL_TEST_HIDDEN=1' % (base, a.get('pid')))
        if base == 'xctest':
            dyld = env.get('DYLD_INSERT_LIBRARIES', '').split(':')
            if not (any(x.endswith('/libMainThreadChecker.dylib') for x in dyld) and any(x.endswith('/guard-board.dylib') for x in dyld)):
                fails.append('xctest pid %s without the main thread checker or the guard: %s' % (a.get('pid'), dyld))
            if env.get('SSH_AUTH_SOCK', '').startswith(OWNER) or not env.get('SSH_AUTH_SOCK'):
                fails.append('xctest pid %s agent socket is not the private absent one' % a.get('pid'))
    return fails


def gate_counts(stage, out):
    fails = []
    def read(name):
        try:
            return L.read_regular(Path(out) / name).decode('utf-8', 'replace')
        except OSError as e:
            fails.append('%s unreadable: %r' % (name, e))
            return ''
    if stage == 'A':
        log = read('xcode-build.stdout')
        if '-warnings-as-errors' not in log:
            fails.append('-warnings-as-errors is not in the build log')
        if '** TEST BUILD SUCCEEDED **' not in log:
            fails.append('the build log has no TEST BUILD SUCCEEDED')
    elif stage == 'B':
        log = read('xcode-test.stdout')
        m = re.search(r'^\S+ Test run with (\d+) tests? in \d+ suites? (passed|failed) after', log, re.M)
        if not m or m[2] != 'passed' or int(m[1]) != SWIFT_TESTS:
            fails.append('Swift tests: wanted %d passed, log says %s' % (SWIFT_TESTS, m[0] if m else 'no run line'))
        if 'Test Suite \'LarsalUITests' in log or 'LarsalUITests/' in log:
            fails.append('LarsalUITests appears in the test log')
        try:
            s = json.loads(read('results.stdout') or '{}')
        except ValueError:
            s = {}
        if s.get('failedTests') != 0 or s.get('skippedTests') != 0 or s.get('expectedFailures') != 0 or s.get('passedTests') != SWIFT_TESTS:
            fails.append('result bundle: wanted %d passed, 0 failed, 0 skipped, 0 expected failures, got %s' % (SWIFT_TESTS, {k: s.get(k) for k in ('passedTests', 'failedTests', 'skippedTests', 'expectedFailures')}))
        a = read('app09.stdout')
        if not re.search(r'^running %d tests$' % APP09_TESTS, a, re.M) or not re.search(r'^test result: ok\. %d passed; 0 failed; 0 ignored' % APP09_TESTS, a, re.M):
            fails.append('APP09: wanted %d of %d, log says %s' % (APP09_TESTS, APP09_TESTS, (re.findall(r'^test result:.*$', a, re.M) or ['no result line'])[-1]))
    return fails


def gate_t(rec, named):
    """Own objects gone; foreign objects unchanged. A new name no allow row names is another program's: listed, not failed."""
    fails = []
    for x in rec['t_cleanup']['left']:
        if x['path'] in named or x['issue'] not in ('no allow row from a process in this sandbox names it', 'birth time outside the attempt window', 'other uid'):
            fails.append('own T object not removed: %s (%s)' % (x['path'], x['issue']))
    rec['t_new_foreign'] = [p for p in rec['t_new_left'] if p not in named]
    fails += ['own T object left: ' + p for p in rec['t_new_left'] if p in named]
    fails += ['foreign T object gone or changed: ' + p for p in rec['t_foreign_gone_or_changed']]
    return fails


def var_tmp_session_names():
    return sorted(n for n in os.listdir(VAR_TMP) if 'test-session' in n)


def read_report(owner, name):
    """What a crash report says of its process, or None when it cannot be parsed."""
    try:
        _, _, rest = L.read_regular(owner + '/Library/Logs/DiagnosticReports/' + name).decode('utf-8', 'replace').partition('\n')
        body = json.loads(rest)
        row = dict(report=name, pid=body['pid'], parent=body['parentPid'], path=body['procPath'], launched=datetime.datetime.strptime(body['procLaunch'], '%Y-%m-%d %H:%M:%S.%f %z').timestamp())
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return row if isinstance(row['pid'], int) and isinstance(row['parent'], int) and isinstance(row['path'], str) else None


def own_name_reports(new_reports, own_names, owner):
    """The new reports that bear an own name, read: name to what it says. A foreign name is listed and not read: README, limit 18."""
    return {n: read_report(owner, n) for n in new_reports if L.REPORT_NAME.match(n) and L.REPORT_NAME.match(n)[1] in own_names}


def starts_of(row):
    return [s[0] + s[1] / 1e6 for s in [row.get('started')] + row.get('later_starts', []) if s]


def report_is_ours(x, trees, root):
    """Why a parsed report of an own name is this lane's, or None. The reporter masks folders, /private/tmp/*/swiftlint, so a real report never names the root: a masked path the root fits counts, if its launch falls in an attempt. A pid must match by start time where its row holds one, each start the sampler read, so a reused pid neither claims another's crash nor hides ours; a row with none goes by the attempt's window. A parent cannot start after its child. What this leaves unseen: README, limit 18."""
    roots = root, root[len('/private'):]
    if x['path'].startswith(tuple(r + '/' for r in roots)):
        return 'its image is under this root'
    masked, star, _ = x['path'].partition('/*/')
    for t in trees:
        if not t['started'] - CLOCK_SLACK <= x['launched'] <= t['read'] + CLOCK_SLACK:
            continue
        if star and any((r + '/').startswith(masked + '/') for r in roots):
            return 'its image reads %s, which this root fits' % x['path']
        tree = t['tree']
        if x['pid'] in tree and (not starts_of(tree[x['pid']]) or any(abs(x['launched'] - s) <= CLOCK_SLACK for s in starts_of(tree[x['pid']]))):
            return 'pid %d is in the process tree' % x['pid']
        if x['parent'] in tree and min(starts_of(tree[x['parent']]), default=0) - CLOCK_SLACK <= x['launched']:
            return 'its parent, pid %d, is in the process tree' % x['parent']
    return None


def gate_host(rec, new_reports, reports, left, session_names, trees, root):
    fails = ['owner sentinel changed: ' + k for k in rec['sentinels_changed']]
    fails += ['process left under the root: %(pid)d %(path)s' % x for x in left]
    fails += ['same-group survivor after exit, killed: pid %(pid)d parent %(parent)d %(image)s' % x for x in rec['group_survivors']]
    fails += ['same-group process still alive after the kill: pid %(pid)d parent %(parent)d %(image)s' % x for x in rec['group_left_after_kill']]
    fails += ['descendant still alive after exit: pid %(pid)s parent %(parent)s %(image)s' % x for x in rec['descendants_alive_after_exit']]
    if rec['group_after_exit'] != 'gone':
        fails.append('process group after exit: ' + rec['group_after_exit'])
    fails += ['left in %s: %s' % (VAR_TMP, n) for n in session_names]
    rec['diagnostic_reports_new'] = sorted(new_reports)
    why = {n: 'it cannot be parsed' if x is None else report_is_ours(x, trees, root) for n, x in reports.items()}
    rec['diagnostic_reports_own'] = sorted(n for n, y in why.items() if y)
    rec['diagnostic_reports_not_ours'] = [dict(report=n, pid=reports[n]['pid'], parent=reports[n]['parent'], path=reports[n]['path']) for n, y in sorted(why.items()) if not y]
    fails += ['crash report during the run: %s: %s' % (n, why[n]) for n in rec['diagnostic_reports_own']]
    return fails


def gate_windows(rec, samples, stage):
    fails = []
    if rec['window_listed_on_screen']:
        fails.append('a window from this run listed on screen')
    if rec['stopped']:
        fails.append('stopped: ' + rec['stopped'])
    if rec['sampler_errors']:
        fails.append('the sampler had errors: %s' % rec['sampler_errors'][:3])
    if stage[0] != 'A' and samples < max(1, rec['seconds'] / 9):  # About every 3 s; one in three kept is the floor.
        fails.append('window samples too few: %d in %s s' % (samples, rec['seconds']))
    return fails


# ---- One attempt.
def attempt(name, stage):
    assert re.fullmatch(r'[A-Za-z0-9-]+', name)
    d = RUNS / name
    d.mkdir(mode=0o700)  # Exclusive: never adopts an earlier run.
    out = OUT / name
    out.mkdir(mode=0o700)
    cap = L.time_left(ATTEMPT_CAP)
    os.umask(0o022)
    profile = gc_profiles.native_profile(TOOL_DIR, str(R), T, OWNER, WITHHELD)
    before = t_listing()
    save(d / 't-before.json', before)
    # Terminals open now are the owner's or other agents': closed, by exact name, for this attempt.
    ttys = sorted(n for n in os.listdir('/dev') if re.fullmatch(r'ttys[0-9]+', n))
    tty_tail = ''.join('(deny file-write* (literal "/dev/%s"))\n(deny file-write-data (literal "/dev/%s"))\n' % (n, n) for n in ttys)
    L.seal_file(d / 'profile.sb', (profile + deny_tail(before) + tty_tail).encode())  # RUNS is outside the lane's write roots.
    env = environment()
    save(d / 'environment.json', env)
    guard_log = OUT / 'guard' / 'general-board.log'
    guard_start = os.lstat(guard_log).st_size if os.path.lexists(guard_log) else 0
    diag_before = L.diag_names(OWNER)
    kind = stage[0]
    L.check_sealed()
    argv = ['/usr/bin/sandbox-exec', '-f', str(L.sealed(d / 'profile.sb')), '/bin/bash', str(L.sealed(TOOL_DIR / 'native-lane.sh')), stage, str(out)]
    rec = dict(attempt=name, stage=stage, argv=argv, cwd=str(S), cap=cap, sentinels_before=L.sentinels(OWNER), stopped=None, needs_at_start=len(needs()))
    rec['started'] = time.time()
    so = (d / 'lane.stdout').open('xb')
    se = (d / 'lane.stderr').open('xb')
    p = subprocess.Popen(argv, cwd=S, env=env, stdin=subprocess.DEVNULL, stdout=so, stderr=se, start_new_session=True)
    rec['pid'] = p.pid
    save(d / 'started.json', rec)
    sampler = Sampler(p.pid, d, kind != 'A')
    sampler.start()
    t0 = time.monotonic()
    state = dict(size=0, change=t0, read=t0)
    stall = STALL.get(kind, 600)

    def check():
        now = time.monotonic()
        if sampler.window_seen.is_set():
            return 'a window from this run listed on screen'
        if now - state['read'] >= 1:
            state['read'] = now
            size = sum(f.stat().st_size for f in out.glob('*.std*') if f.is_file())
            if size != state['size']:
                state['size'], state['change'] = size, now
        return 'no output for %d seconds' % stall if now - state['change'] > stall else None

    rec['stopped'] = L.wait_exit(p, t0 + cap, check)
    if rec['stopped']:
        L.stop_group(p, 20)
    rec['ended'] = time.time()
    rec['seconds'] = round(rec['ended'] - rec['started'], 1)
    so.close()
    se.close()
    time.sleep(2)
    sampler.stop_flag.set()
    sampler.join(timeout=10)
    # The leader stays unreaped until its group is named and has had the SIGKILL. Group first; only then the log and T.
    closed = L.close_group(p)
    rec['exit'] = closed['exit']
    rec['group_survivors'], rec['group_left_after_kill'] = closed['survivors'], closed['left_after_kill']
    rec['group_after_exit'] = 'gone' if closed['group_absent'] else 'still present'
    # Read after the kill. Any image counts, so a tracked process that exec'd is seen; its image and parent are the receipt's, and nothing here signals it.
    alive = {q: image(q) for q in sampler.tree if q != p.pid}
    parents = {x['pid']: x for x in L.group_rows_any(sorted(q for q, a in alive.items() if a))}
    rec['descendants_alive_after_exit'] = [dict(pid=q, image=a, first_image=sampler.tree[q]['path'], parent=parents.get(q, {}).get('parent')) for q, a in sorted(alive.items()) if a]
    save(d / 'process-tree.json', sorted(sampler.tree.values(), key=lambda r: r['seconds']))
    save(d / 'process-outside-tree.json', sorted(sampler.other.values(), key=lambda r: r['seconds']))
    arg_rows = list(sampler.args.values()) + sampler.later_args
    save(d / 'process-args.json', arg_rows)
    save(d / 'window-rows.json', sampler.window_rows)
    rec['sampler_errors'] = sampler.__dict__.get('errors', [])[:10]
    rec['window_listed_on_screen'] = sampler.window_seen.is_set()
    time.sleep(8)  # Rows reach log show up to about 5 seconds late.
    names = set(TOOLS) | {os.path.basename(p) for r in list(sampler.tree.values()) + list(sampler.other.values()) for p in images_of(r)}
    rec['log'], created, named, sensitive = query_log(d, rec['started'], rec['ended'], names, set(sampler.tree))
    rec['t_cleanup'] = t_cleanup(before, (rec['started'], rec['ended']), created, set(sampler.tree))
    after = t_listing()
    save(d / 't-after.json', after)
    was = {r['path'].lower(): r['inode'] for r in before}
    rec['t_new_left'] = [r['path'] for r in after if r['path'].lower() not in was]
    rec['t_foreign_gone_or_changed'] = [k for k, v in was.items() if not any(r['path'].lower() == k and r['inode'] == v for r in after)]
    rec['sentinels_after'] = L.sentinels(OWNER)
    rec['sentinels_changed'] = [k for k in rec['sentinels_before'] if rec['sentinels_before'][k] != rec['sentinels_after'][k]]
    rec['window_samples'] = sampler.window_samples
    guard_text, guard_unread = b'', []
    if os.path.lexists(guard_log):
        try:  # The lane could leave a link or a FIFO here: nothing is followed, nothing is copied.
            guard_text = L.read_regular(guard_log, guard_start)
        except OSError as e:
            guard_unread = ['the guard failed: its log cannot be read: %r' % e]
    (d / 'general-board.log').write_bytes(guard_text)
    xctest = xctest_pids(sampler.tree)
    rec['fork_window_once'] = [dict(r, grants=sorted({x['target'] for x in sensitive if x['pid'] == r['pid']})) for r in sampler.tree.values() if forked_once(r, sampler.tree)]
    guard_fails, rec['guard'] = gate_guard(guard_text.decode('utf-8', 'replace'), xctest)
    guard_fails = guard_unread + guard_fails
    failures = []
    if rec['exit'] != 0:
        failures.append('step exit %s' % rec['exit'])
    if kind in 'ABG' and (rec['log']['exit'] != 0 or not rec['log']['kept']):
        failures.append('no kernel rows read: log exit %s, %s rows' % (rec['log']['exit'], rec['log']['kept']))
    if kind == 'B' and not xctest:
        failures.append('xctest was never sampled')
    failures += gate_windows(rec, sampler.window_samples, stage)
    failures += gate_sensitive(sensitive)
    failures += gate_identity(sensitive, sampler.tree)
    failures += gate_outside(sampler.other, sampler.args, str(R), sampler.tree)
    if kind == 'A':
        failures += gate_xctestrun(S / 'target/xcode/Build/Products')
    failures += guard_fails
    failures += gate_env(arg_rows, kind == 'B')
    failures += gate_counts(stage, out)
    failures += gate_t(rec, named)
    LANE_TREES.append(dict(tree=sampler.tree, started=rec['started'], read=time.time()))
    new_reports = L.diag_names(OWNER) - diag_before
    failures += gate_host(rec, new_reports, own_name_reports(new_reports, names, OWNER), L.images_under(R), var_tmp_session_names(), LANE_TREES, str(R))
    rec['gate_failures'] = failures
    save(d / 'gates.json', dict(failures=failures, guard=rec['guard'], window_samples=sampler.window_samples, sensitive_totals={t: sum(r['count'] for r in sensitive if r['target'] == t) for t in SENSITIVE}, sensitive_processes=sorted({(r['target'], r['process']) for r in sensitive}), t_new_foreign=rec['t_new_foreign'], diagnostic_reports_new=rec['diagnostic_reports_new'], diagnostic_reports_own=rec['diagnostic_reports_own'], diagnostic_reports_not_ours=rec['diagnostic_reports_not_ours']))
    save(d / 'receipt.json', rec)
    rec['safety'] = [x for x in failures if x.startswith(('a window', 'stopped: a window', 'owner sentinel', 'general board', 'the guard failed', 'sensitive grant', 'process left', 'same-group process still', 'foreign T object', 'a process outside', 'a test bundle'))]
    L.say('native attempt', name, 'exit', rec['exit'], 'seconds', rec['seconds'], 'gate failures', len(failures))
    return rec


# ---- Setup: folders, the two small programs, SwiftLint. Runs outside the sandbox; the profile keeps bin read-only for the lane.
def setup():
    for n in ('home', 'tmp', 'cache', 'instance', 'modules', 'compiler-tmp', 'lane-out', 'lane-out/guard', 'runs', 'bin'):
        (R / n).mkdir(mode=0o700, parents=True, exist_ok=True)
    env = environment()
    clang = [env['CC'], '-isysroot', env['SDKROOT'], '-mmacosx-version-min=14.0']
    small = dict(PATH='/usr/bin:/bin', HOME=str(R / 'home'), TMPDIR=str(R / 'tmp') + '/', DEVELOPER_DIR=env['DEVELOPER_DIR'], CLANG_MODULE_CACHE_PATH=env['CLANG_MODULE_CACHE_PATH'])
    subprocess.run(clang + ['-O1', '-DPRIVATE_TMP="%s/compiler-tmp/"' % R, '-o', 'bin/swiftc', 'tool/swiftc-launch.c'], cwd=R, env=small, check=True)
    dylib = L.guard_dylib(R, TOOL_DIR)
    # A copy, so the profile keeps the owner's home closed. check.sh's --path answer points here because HOME does.
    lint = Path(L.swiftlint_path(S, str(R / 'home')))
    lint.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(L.swiftlint_path(S, OWNER), lint)
    lint.chmod(0o755)
    want = gc_pins.table(TOOL_DIR, 'routes.json')['binaries']['swiftlint']
    if L.sha(lint) != want:
        raise L.Custody('SwiftLint hash %s differs from the table %s' % (L.sha(lint), want))
    return {p: L.sha(p) for p in (str(R / 'bin/swiftc'), str(dylib), str(lint))}


def run(ctx, attempts=(('G1', 'G'), ('A1', 'A'), ('B1', 'B'))):
    """Setup, then G, A and B, one attempt each, no retry. Only a safety reason skips what is left."""
    root = ctx['R']
    subprocess.run(['/bin/cp', '-cRp', str(root / 'e'), str(root / 's')], check=True, env=L.SMALL_ENV)
    expected = [int(x) for x in L.read_regular(Path(ctx['tool'], 'tables/native-expected.txt')).split()]
    assert len(expected) == 2, 'native-expected.txt holds one line: the Swift total and the APP09 total'
    configure(root, ctx['tool'], ctx['T'], ctx.get('owner', L.OWNER), L.rust_toolchain(root / 's'), expected, ctx.get('withheld'))
    pins = setup()
    out = dict(step='native', reasons=[], safety=None, attempts={}, pins=pins, expected=dict(swift=expected[0], app09=expected[1]))
    for name, stage in attempts:
        if out['safety'] or L.stopping():
            out['reasons'].append(name + ' not started: ' + str(out['safety'] or L.stopping()))
            continue
        if stage == 'B':  # The last read before the tests start. A plan that moved is not run.
            bad = gate_xctestrun(S / 'target/xcode/Build/Products')
            if bad:
                out['reasons'] += [name + ' not started: ' + x for x in bad]
                out['safety'] = bad
                continue
        ctx['hold']()
        bad = L.compare_copy(S, R, ignore=('target',))[0]  # New names are the build's own; the end compare reads them.
        if bad:
            raise L.Custody('native copy changed before attempt %s: %s' % (name, bad[:5]))
        L.stop_on_configs(S, R / 'home/.cargo', 'attempt ' + name)
        with ctx['busy']():
            rec = attempt(name, stage)
        out['attempts'][name] = {k: rec.get(k) for k in ('exit', 'seconds', 'stopped', 'gate_failures', 'window_samples', 'group_after_exit', 'group_survivors', 'descendants_alive_after_exit', 'guard', 'diagnostic_reports_new', 'diagnostic_reports_not_ours', 'sentinels_changed', 't_new_foreign', 'safety', 'fork_window_once')}
        out['reasons'] += [name + ': ' + x for x in rec['gate_failures']]
        out['safety'] = rec['safety'] or None
    moved = {p: h for p, h in pins.items() if L.sha(p) != h}
    if moved:
        out['reasons'].append('SwiftLint or guard library changed during the run: %s' % sorted(moved))
    return out
