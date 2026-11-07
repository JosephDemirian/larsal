"""The Rust step, route R2b with its pins computed per run: build, capture with the recorder, reconcile, import screen, byte checks, admissions from one table, plans, then every program alone under its profile through the helper. No test filter, no retry."""
import hashlib, json, os, re, resource, shutil, stat, subprocess, time
from pathlib import Path
import gc_lib as L
import gc_pins, gc_profiles

HELPER, CONFIG, RECORDER = 'harness-cli-pty-r3-runner.py', 'runner-cli-pty-r3-config.json', 'capture-launch-r4.py'
OT = ['test', '--offline', '--locked']
SELECT = L.load(Path(__file__).resolve().parent / 'tables/routes.json')['select']  # Lane: [selectors, tail]. The table holds what the g2 text pinned beside it says.
LANES = list(SELECT)
BASE_ENTRY = dict(classes=[], profile=gc_pins.BASE)
RUN_CAPS = [('workspace', 1200), ('sync', 600), ('net', 120), ('release', 300), ('release-browser', 120)]  # app09 runs in the native step.
BUILD_CAP, CAPTURE_CAP, NM_CAP = 1500, 300, 30
RECORD_FIELDS = {'stage', 'payload_executed', 'pid', 'time_ns', 'argv', 'cwd', 'environment'}
CARGO_ADDED = re.compile(r'CARGO(_.*)?|DYLD_FALLBACK_LIBRARY_PATH|LC_CTYPE|RUSTUP_TOOLCHAIN_SOURCE|RUST_RECURSION_COUNT|__CF_USER_TEXT_ENCODING')
TEST_CONTROL = re.compile(r'RUST_TEST|THREADS|FILTER|SKIP|NEXTEST|SHUFFLE|IGNORE')
SSHD_NAMES = ('sshd', 'sshd-session', 'sshd-auth')
INFO = {'SecKey': re.compile(r'^_SecKey[A-Za-z0-9_]*$'), 'kSec': re.compile(r'^_kSec[A-Za-z0-9_]*$'), 'objc_keychain_classes': re.compile(r'^_OBJC_(?:CLASS|METACLASS)_\$_(?:\w*Keychain\w*|LAContext|SFAuthorization\w*|TKToken\w*|ASAuthorization\w*)$')}


def cargo(lane, no_run=False):
    sel, tail = SELECT[lane]
    end = ['--no-run', '--message-format=json'] if no_run else tail + ['--no-fail-fast']
    return [L.OWNER + '/.cargo/bin/cargo'] + OT + sel + end


def lane_env(r, lane, toolchain, owner=L.OWNER):
    """The reviewed capture environment; only the roots and the toolchain name are parameters."""
    rt, tc, rust = r + '/run/env/runtime', L.TC, owner + '/.rustup/toolchains/' + toolchain + '/bin'
    return dict(
        AR=tc + '/ar', CARGO_AUDIT_NO_FETCH='true', CARGO_BUILD_JOBS='1', CARGO_HOME=r + '/cargo-home', CARGO_NET_OFFLINE='true',
        CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=tc + '/clang', CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=r + '/helpers/' + RECORDER, CARGO_TARGET_DIR=r + '/target',
        CC=tc + '/clang', CFFIXED_USER_HOME=rt + '/home', CLANG_MODULE_CACHE_PATH=rt + '/modules', CXX=tc + '/clang++', DEVELOPER_DIR=L.XCODE, HOME=rt + '/home',
        LARSAL_CAPTURE_LAUNCH_DIR=r + '/state/capture/' + lane, LARSAL_TEST_HIDDEN='1', LARSAL_TEST_INSTANCE_DIR=r + '/run/instance', MAC_CHROMIUM_TMPDIR=r + '/run/tmp',
        PATH=':'.join([tc, L.XCODE + '/usr/bin', owner + '/.cargo/bin', '/opt/homebrew/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', RANLIB=tc + '/ranlib', RUSTC=rust + '/rustc', RUSTDOC=rust + '/rustdoc', RUSTUP_AUTO_INSTALL='0', RUSTUP_HOME=owner + '/.rustup', RUSTUP_TOOLCHAIN=toolchain,
        SDKROOT=L.XCODE + '/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk', SSH_AUTH_SOCK=r + '/run/instance/no-owner-ssh.sock', SWIFT_MODULECACHE_PATH=rt + '/swift-modules',
        TEST_RUNNER_CFFIXED_USER_HOME=rt + '/home', TEST_RUNNER_HOME=rt + '/home', TEST_RUNNER_LARSAL_TEST_HIDDEN='1', TEST_RUNNER_LARSAL_TEST_INSTANCE_DIR=r + '/run/instance',
        TEST_RUNNER_SSH_AUTH_SOCK=r + '/run/instance/no-owner-ssh.sock', TEST_RUNNER_TMPDIR=r + '/run/tmp/', TMPDIR=r + '/run/tmp/',
        XDG_CACHE_HOME=rt + '/cache', XDG_CONFIG_HOME=rt + '/config', XDG_DATA_HOME=rt + '/data')


def prepare(R, tool):
    r = R / 'r'
    dirs = ['cargo-home', 'target', 'run/env/runtime/home', 'run/env/runtime/cache', 'run/env/runtime/config', 'run/env/runtime/data', 'run/env/runtime/modules', 'run/env/runtime/swift-modules', 'run/tmp', 'run/instance', 'helpers', 'profiles', 'inputs', 'state/harness-events', 'state/replay', 'state/run-lanes', 'tmp', 'home', 'cache', 'proof/build', 'proof/capture', 'proof/import'] + ['state/capture/' + x for x in LANES]
    L.mkdirs(r, *[r / d for d in dirs])
    # Outside every write root of the family, read only, compared before every use.
    for n, t in gc_profiles.rust_profiles(str(r)).items():
        L.seal_file(r / 'profiles' / n, t.encode())
    os.chmod(r / 'profiles', 0o500)
    L.mkdirs(r / 'run/env/runtime/guard')
    shutil.copyfile(tool / HELPER, r / HELPER)
    (r / HELPER).chmod(0o700)
    shutil.copyfile(tool / RECORDER, r / 'helpers' / RECORDER)
    (r / 'helpers' / RECORDER).chmod(0o700)
    subprocess.run(['/bin/cp', '-cRp', str(R / 'e'), str(r / 'source')], check=True, env=L.SMALL_ENV)
    os.chmod(r / 'source', 0o700)
    shutil.copyfile(R / 'manifest.json', r / 'inputs/source-manifest.json')
    (r / 'inputs/source-manifest.json').chmod(0o600)
    return r


# ---- Build.
def build(r, toolchain):
    rows, streams = [], {}
    P = r / 'proof/build'
    for lane in LANES:
        L.stop_on_configs(r / 'source', r / 'cargo-home', 'build ' + lane)
        env = lane_env(str(r), lane, toolchain)
        env['CARGO_BUILD_JOBS'] = '4'
        L.check_sealed()
        row = L.held([L.SANDBOX, '-f', L.sealed(r / 'profiles/build-cargo.sb')] + cargo(lane, True), r / 'source', env, P / (lane + '.stdout'), P / (lane + '.stderr'), L.time_left(BUILD_CAP))
        row['lane'] = lane
        rows.append(row)
        L.say('rust build', lane, 'exit', row['exit'], row['seconds'])
        if not L.row_clean(row):
            break
        streams[lane] = [json.loads(x) for x in (P / (lane + '.stdout')).read_text().splitlines() if x.startswith('{')]
    return rows, streams


def empty_cargo_home(r):
    """The reviewed capture requires it empty; it must hold no crate content, only Cargo's own cache marks."""
    ch = r / 'cargo-home'
    bad = [str(Path(d) / n) for d, _, fs in os.walk(ch) for n in fs if n.endswith(('.crate', '.rs', '.toml'))]
    assert not bad, 'Cargo home holds crate content: %s' % bad[:5]
    for n in os.listdir(ch):
        q = ch / n
        shutil.rmtree(q) if q.is_dir() and not q.is_symlink() else q.unlink()


def harness_rows(stream):
    return {x['executable']: x for x in stream if x.get('reason') == 'compiler-artifact' and x.get('executable') and x['profile']['test']}


# ---- Capture.
def capture_set(r, lane, row, stream):
    d = r / 'state/capture' / lane
    expected = harness_rows(stream)
    recorder = str(r / 'helpers' / RECORDER)
    records, seen = [], set()
    for p in d.iterdir():
        x = L.pin(p)
        assert x['kind'] == stat.S_IFREG and x['mode'] == 0o600 and x['uid'] == os.getuid() and x['nlink'] == 1, str(p)
        c = L.load(p)
        assert set(c) == RECORD_FIELDS and c['stage'] == 'discovery-only' and c['payload_executed'] is False and type(c['pid']) is int and p.name == str(c['pid']) + '.json', str(p)
        assert type(c['time_ns']) is int and row['wall_start_ns'] <= c['time_ns'] <= row['wall_end_ns'], str(p)
        assert len(c['argv']) == 1 and c['argv'][0] in expected and c['argv'][0] not in seen, str(p)
        assert c['cwd'] == c['environment']['CARGO_MANIFEST_DIR'], str(p)
        seen.add(c['argv'][0])
        records.append(dict(raw=dict(path=str(p), sha256=x['sha256']), record=c, semantic=semantic(expected[c['argv'][0]])))
    assert seen == set(expected), ('capture set differs from the no-run stream', lane, sorted(seen ^ set(expected))[:5])
    stderr = Path(row['stderr']).read_text(encoding='utf-8', errors='strict')
    exits = re.findall(r"^  process didn't exit successfully: `([^`]+)` \(exit status: ([0-9]+)\)$", stderr, re.M)
    assert len(exits) == len(records) and all(code == '78' for _, code in exits), ('recorder exit status', lane)
    assert {cmd for cmd, _ in exits} == {recorder + ' ' + p for p in seen}
    assert len(re.findall('exit status:', stderr)) == len(records) and 'Traceback (most recent call last)' not in stderr
    totals = []
    for line in stderr.splitlines():
        if line.startswith('error:') and not line.startswith('error: test failed, to rerun pass '):
            m = re.fullmatch(r'error: ([0-9]+) targets? failed:', line)
            assert m, ('unexpected Cargo error', line)
            totals.append(int(m[1]))
    assert len(totals) <= 1 and all(n == len(records) for n in totals), ('contradictory Cargo aggregate', totals, len(records))
    records.sort(key=lambda x: (x['record']['time_ns'], x['record']['pid']))
    return records


def check_environment(records, lane_environment):
    """Replaces the old per-program oracle: the recorded child environment is the lane's, plus Cargo's own variables, and holds no test control."""
    for x in records:
        e = x['record']['environment']
        for k, v in lane_environment.items():
            assert k == 'PATH' or e.get(k) == v, ('recorded environment differs', x['raw']['path'], k)
        assert e['PATH'].endswith(lane_environment['PATH']), ('recorded PATH', x['raw']['path'])
        extra = [k for k in e if k not in lane_environment and not CARGO_ADDED.fullmatch(k)]
        assert not extra, ('recorded environment has an unknown variable', x['raw']['path'], extra)
        control = [k for k in e if TEST_CONTROL.search(k)]
        assert not control, ('recorded environment has a test control', x['raw']['path'], control)


def semantic(row):
    return dict(package_id=row['package_id'], target=row['target']['name'], kind=row['target']['kind'], crate_types=row['target']['crate_types'], src_path=row['target']['src_path'], profile=row['profile'], features=row['features'], fresh=row['fresh'])


def is_code(p, x):
    if not x or x['kind'] != stat.S_IFREG:
        return False
    if x['mode'] & 0o111 or Path(p).suffix in ('.rlib', '.rmeta', '.a', '.o', '.dylib'):
        return True
    return L.head(p, 4) == bytes.fromhex('cffaedfe')


def capture_reconcile(before, after):
    """A code path may change only as the same bytes on a new inode. Anything else that is code is an issue."""
    issues, rebound, other = [], 0, 0
    for p in sorted(set(before) | set(after)):
        old, new = before.get(p), after.get(p)
        if old == new:
            continue
        if not is_code(p, old) and not is_code(p, new):
            other += 1
        elif old and new and all(old.get(k) == new.get(k) for k in ('device', 'uid', 'gid', 'kind', 'mode', 'size', 'nlink', 'mtime_ns', 'flags', 'sha256', 'link')):
            rebound += 1
        else:
            issues.append(p)
    return dict(issues=issues, same_bytes_new_inode=rebound, non_code_changes=other)


def capture(r, toolchain, streams, before):
    P = r / 'proof/capture'
    rows, plans_in = [], {}
    start = time.monotonic()
    for lane in LANES:
        env = lane_env(str(r), lane, toolchain)
        assert not list((r / 'state/capture' / lane).iterdir())
        wall = time.time_ns()
        L.check_sealed()
        row = L.held([L.SANDBOX, '-f', L.sealed(r / 'profiles/capture-cargo.sb')] + cargo(lane), r / 'source', env, P / (lane + '.stdout'), P / (lane + '.stderr'), L.time_left(CAPTURE_CAP))
        row.update(lane=lane, wall_start_ns=wall, wall_end_ns=time.time_ns(), stderr=str(P / (lane + '.stderr')))
        rows.append(row)
        L.say('rust capture', lane, 'exit', row['exit'], row['seconds'])
        assert row['exit'] == 101 and not row['stopped'] and not row['survivors'] and row['group_absent'], ('capture row', lane, row['exit'])
        records = capture_set(r, lane, row, streams[lane])
        check_environment(records, env)
        plans_in[lane] = records
    L.save(P / 'rows.json', rows)
    after = L.tree(r / 'target')
    rec = capture_reconcile(before, after)
    L.save(P / 'reconcile.json', rec)
    assert not rec['issues'], ('capture changed code', rec['issues'][:5])
    return plans_in, round(time.monotonic() - start, 1), after


# ---- The strict import screen, per run.
def symbols(raw):
    lines = raw.decode('utf-8', 'strict').splitlines()
    assert lines and all(re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*', x) for x in lines), 'empty/malformed undefined-symbol stream'
    assert not any(re.search(r'_Sec(?:Item|Keychain|AccessControl)', x) for x in lines), 'forbidden import'
    return len(lines)


def parser_check():
    """Per run, the strict parser refuses each dirty stream and counts a clean one."""
    assert symbols(b'_free\n_malloc\n') == 2
    for raw in (b'', b'\n', b'foo:\n_free\n', b'000 U _free\n', b'_SecItemCopyMatching\n', b'_SecKeychainOpen\n', b'_SecAccessControlCreateWithFlags\n', b'error: failed\n', b'\xff', b' _free\n'):
        try:
            symbols(raw)
        except (AssertionError, UnicodeDecodeError):
            continue
        raise AssertionError('the screen parser took a dirty stream: %r' % raw)


def executables(target):
    """Every program the build made: regular, executable, Mach-O MH_EXECUTE, under debug and release, without build scripts."""
    out = []
    for top in ('debug', 'release'):
        for d, ns, fs in os.walk(os.path.join(target, top)):
            rel = os.path.relpath(d, os.path.join(target, top)).split('/')[0]
            if rel in ('build', 'incremental', '.fingerprint'):
                ns[:] = []
                continue
            for n in fs:
                p = os.path.join(d, n)
                s = os.lstat(p)
                if stat.S_ISREG(s.st_mode) and s.st_mode & 0o111:
                    h = L.head(p, 16)
                    if h[:4] == bytes.fromhex('cffaedfe') and int.from_bytes(h[12:16], 'little') == 2:
                        out.append(p)
    return sorted(out)


def screen(r):
    """Returns the ledger row and each program's undefined symbols; the symbols are read by the byte checks and kept nowhere else."""
    parser_check()
    P, rs = r / 'proof/import', str(r)
    env = dict(HOME=rs + '/home', CFFIXED_USER_HOME=rs + '/home', TMPDIR=rs + '/tmp/', XDG_CACHE_HOME=rs + '/cache', DEVELOPER_DIR=L.XCODE, PATH='/usr/bin:/bin', SSH_AUTH_SOCK=rs + '/no-ssh.sock', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', CLANG_MODULE_CACHE_PATH=rs + '/cache/modules', SWIFT_MODULECACHE_PATH=rs + '/cache/swift-modules')

    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024))

    ledger, refusals, imports = [], [], {}
    tools = lambda: [L.sha(L.NM), L.sha(L.SANDBOX), L.sha(L.sealed(r / 'profiles/import-admit.sb'))]
    before = tools()
    for i, path in enumerate(executables(rs + '/target')):
        pinned = L.pin(path)
        out, err = P / ('%03d.stdout' % i), P / ('%03d.stderr' % i)
        row = L.held([L.SANDBOX, '-f', r / 'profiles/import-admit.sb', L.NM, '-u', path], r, env, out, err, L.time_left(NM_CAP), preexec=limits)
        raw = out.read_bytes()
        refuse = []
        if row['exit'] != 0 or row['stopped'] or row['survivors']:
            refuse.append('exit')
        if err.stat().st_size:
            refuse.append('stderr')
        if L.pin(path) != pinned:
            refuse.append('pin-drift')
        try:
            count = symbols(raw)
        except (AssertionError, UnicodeError) as e:
            count = None
            refuse.append('grammar-or-forbidden: ' + repr(e)[:200])
        words = raw.decode('utf-8', 'replace').split()
        imports[path] = set(words)
        info = {k: sorted(s for s in words if v.search(s)) for k, v in INFO.items()}
        ledger.append(dict(path=path, sha256=pinned['sha256'], symbols=count, seconds=row['seconds'], refusal=refuse, information_imports={k: v for k, v in info.items() if v}))
        if refuse:
            refusals.append(dict(path=path, refusal=refuse))
    result = dict(reads=len(ledger), refusals=refusals, tools_equal=before == tools(), ledger=ledger, passed=not refusals and before == tools() and bool(ledger))
    L.save(r / 'proof/import-screen.json', result)
    return result, imports


# ---- The byte checks, per run, for every row still holding its grant.
def key_of(lane, x):
    return '%s:%s/%s' % (lane, x['record']['environment']['CARGO_PKG_NAME'], x['semantic']['target'])


def byte_withheld(r, tool, records, imports, withheld, streams=None):
    """R2b's byte evidence, read again from this build, and where the build took each pinned crate from. A failure withholds the row the same way a moved pin does. Needs rows are in the moved-crate read: native runs later and leaves them out."""
    pins, out = gc_pins.table(tool, 'pins.json'), {}
    folders = {}
    for stream in (streams or {}).values():
        for name, where in gc_pins.package_folders(stream, str(r / 'source')).items():
            folders.setdefault(name, set()).update(where)
    for key, row in pins['rows'].items():
        bad = gc_pins.moved_crates(row, folders)
        if bad and key not in withheld:
            out[key] = bad
    for lane in LANES:
        for x in records[lane]:
            key, exe = key_of(lane, x), x['record']['argv'][0]
            row = pins['rows'].get(key)
            if row and key not in withheld:
                bad = gc_pins.outside_folder(key, row, str(r / 'source'), x['semantic'].get('src_path'), x['record']['environment'].get('CARGO_MANIFEST_DIR'))
                if row.get('checks'):
                    bad += gc_pins.byte_failures(pins, key, L.read_regular(exe), imports.get(exe, set()), str(r / 'target/tmp'))
                if bad:
                    out.setdefault(key, []).extend(bad)
    return out


# ---- Admissions and plans, from one table.
def admissions(r, tool, records, manifest_sha, withheld=(), dylib=None):
    """By lane, crate and target name, from the reviewed table, for a row whose pin and byte checks hold. Any other program gets the base profile and no class, so it fails closed if it needs more, and is listed.
    A row holding the board or the window line loads the guard library."""
    table = L.load(tool / 'tables/programs.json')
    rows, new = [], []
    for lane in LANES:
        for x in records[lane]:
            c = x['record']
            exe = c['argv'][0]
            key = key_of(lane, x)
            x['key'] = key
            if key not in table:
                new.append(key)
            entry = BASE_ENTRY if key in withheld else table.get(key, BASE_ENTRY)
            row = dict(path=exe, sha256=L.sha(exe), identity=L.identity(exe), classes=entry['classes'], binding=key)
            if entry['profile'] != gc_pins.BASE:
                base = L.sealed(r / 'profiles' / entry['profile'])
                row['runtime_base'] = dict(path=str(base), sha256=L.sha(base))
                if dylib and gc_profiles.holds_board(L.read_regular(base).decode()):
                    # The test program writes here; the driver reads it with no link followed and fails the run on what it says.
                    row['guard'] = dict(path=str(dylib), sha256=L.sha(dylib), log=str(r / 'run/env/runtime/guard' / (Path(exe).name + '.log')))
            assert row['identity']['mode'] == 0o700, exe
            rows.append(row)
    adm = r / 'state/admissions.json'
    L.save(adm, dict(version=1, source_manifest_sha256=manifest_sha, artifacts=rows))
    os.chmod(adm, 0o600)
    return adm, sorted(new)


def check_admitted(adm, after, ledger):
    """C1-08's gap: what is admitted must be what the capture compare and the screen saw."""
    for x in L.load(adm)['artifacts']:
        saw = {(after.get(x['path']) or {}).get('sha256'), ledger.get(x['path'])}
        if saw != {x['sha256']}:
            raise L.Custody('admitted bytes differ from the capture tree or the screen ledger: %s' % x['path'])


def materialize(r, tool, records, withheld=(), dylib=None, after=None, ledger=None):
    manifest = r / 'inputs/source-manifest.json'
    manifest_sha = L.sha(manifest)
    adm, new = admissions(r, tool, records, manifest_sha, withheld, dylib)
    if after is not None:
        check_admitted(adm, after, ledger)
    rs = str(r)
    config = dict(version=1, admissions=str(adm), admissions_sha256=L.sha(adm), artifact_roots=[rs + '/target/debug', rs + '/target/release'], audit_dir=rs + '/state/harness-events', fixture_root=rs, nm_sha256=L.sha(L.NM), runtime_base=rs + '/profiles/harness-runtime-base.sb', runtime_base_sha256=L.sha(L.sealed(r / 'profiles/harness-runtime-base.sb')), sandbox_sha256=L.sha(L.SANDBOX), source_manifest=str(manifest), source_manifest_sha256=manifest_sha)
    cfg = r / CONFIG
    L.save(cfg, config)
    cfg.chmod(0o600)
    helper = rs + '/' + HELPER
    hs, cs = L.sha(helper), L.sha(cfg)
    admitted = {x['path']: x for x in L.load(adm)['artifacts']}
    plan_sha, caps = {}, dict(RUN_CAPS, app09=300)
    for lane in LANES:
        rows = []
        for i, x in enumerate(records[lane]):
            c = x['record']
            exe = c['argv'][0]
            env = dict(c['environment'])
            env.update(CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=helper, LARSAL_HARNESS_RUNNER_SHA256=hs, LARSAL_HARNESS_CONFIG_SHA256=cs)
            env.pop('LARSAL_CAPTURE_LAUNCH_DIR')
            base = exe.rsplit('/', 1)[1]
            stem, tail = base.rsplit('-', 1)
            rows.append(dict(argv=[helper, exe], binding=dict(x['semantic'], key=x['key'], lane=lane), cap=caps[lane], capture=x['raw']['path'], capture_sha256=x['raw']['sha256'], cwd=c['cwd'], environment=env, executable=exe, executable_sha256=admitted[exe]['sha256'], identity=admitted[exe]['identity'], guard=admitted[exe].get('guard'), target='%03d-%s-%s' % (i, stem, tail)))
        p = r / 'state/replay' / (lane + '-replay-plan.json')
        L.save(p, dict(lane=lane, batch_size=1, lane_cap_seconds=caps[lane], targets=rows))
        plan_sha[lane] = L.sha(p)
    own = [x['path'] for x in L.load(adm)['artifacts'] if x['binding'] == 'workspace:larsal-sshagent/own_agent']
    assert len(own) <= 1, 'the one program that starts the real sshd must be one program: %s' % own
    binding = dict(admissions=str(adm), admissions_sha256=L.sha(adm), audit_dir=rs + '/state/harness-events', config=str(cfg), config_sha256=cs, helper=helper, helper_sha256=hs, lane_caps=caps, plan_sha256=plan_sha, source=rs + '/source', source_manifest=str(manifest), source_manifest_sha256=manifest_sha, ssh_rc=L.OWNER + '/.ssh/rc', ssh_watch=[L.OWNER + '/.ssh', L.OWNER + '/.ssh/known_hosts'], ssh_watch_target=dict(lane='workspace', path=own[0] if own else None))
    bp = r / 'state/replay/replay-binding.json'
    L.save(bp, binding)
    return binding, L.sha(bp), new


def custody(B, source_rows=False):
    assert L.sha(B['helper']) == B['helper_sha256'] and L.sha(B['config']) == B['config_sha256'] and L.sha(B['admissions']) == B['admissions_sha256'] and L.sha(B['source_manifest']) == B['source_manifest_sha256']
    if source_rows:
        for x in L.load(B['source_manifest'])['rows']:
            f = Path(B['source']) / x['path']
            assert stat.S_IMODE(f.lstat().st_mode) == x['mode'], x['path']
            if x['kind'] == 'symlink':
                assert hashlib.sha256(os.readlink(f).encode()).hexdigest() == x['sha256'], x['path']
            elif x['kind'] == 'file':
                assert L.sha(f) == x['sha256'], x['path']
    for x in L.load(B['admissions'])['artifacts']:
        assert L.identity(x['path']) == x['identity'] and L.sha(x['path']) == x['sha256'], x['path']


def check_plan(r, lane, B, binding_sha):
    """The binding pins each plan and its cap, and every row answers to its raw capture and its admission."""
    P = r / 'state/replay'
    assert L.sha(P / 'replay-binding.json') == binding_sha and L.sha(P / (lane + '-replay-plan.json')) == B['plan_sha256'][lane]
    plan = L.load(P / (lane + '-replay-plan.json'))
    rows = plan['targets']
    assert plan['lane'] == lane and plan['batch_size'] == 1 and plan['lane_cap_seconds'] == B['lane_caps'][lane] and rows
    assert len({x['executable'] for x in rows}) == len(rows) == len({x['target'] for x in rows})
    admitted = {x['path']: x for x in L.load(B['admissions'])['artifacts']}
    last = None
    for i, x in enumerate(rows):
        assert L.sha(x['capture']) == x['capture_sha256']
        c = L.load(x['capture'])
        assert c['payload_executed'] is False and x['argv'] == [B['helper'], *c['argv']] and x['cwd'] == c['cwd'] and len(c['argv']) == 1
        order = (c['time_ns'], c['pid'])
        assert x['target'].startswith('%03d-' % i) and (last is None or last < order)
        last = order
        assert x['cap'] == B['lane_caps'][lane] and x['executable'] == x['argv'][1]
        a = admitted[x['executable']]
        assert a['sha256'] == x['executable_sha256'] and a['identity'] == x['identity']
        want = dict(c['environment'])
        want.update(CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER=B['helper'], LARSAL_HARNESS_RUNNER_SHA256=B['helper_sha256'], LARSAL_HARNESS_CONFIG_SHA256=B['config_sha256'])
        want.pop('LARSAL_CAPTURE_LAUNCH_DIR', None)
        assert x['environment'] == want
    own = B['ssh_watch_target']['path']
    assert [x['executable'] for x in rows if x['executable'] == own] == ([own] if own and lane == B['ssh_watch_target']['lane'] else [])
    return rows


# ---- One lane.
def watch(B):
    out = {}
    for p in B['ssh_watch']:
        try:
            s = os.lstat(p)
            out[p] = dict(device=s.st_dev, inode=s.st_ino, mode=s.st_mode, size=s.st_size, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns, uid=s.st_uid, nlink=s.st_nlink)
        except FileNotFoundError:
            out[p] = None
    return out


def refusal(B, pid, since):
    try:
        e = L.load(Path(B['audit_dir']) / str(pid) / 'event.json')
    except (OSError, ValueError):
        return dict(error='no helper event for this PID')
    if e.get('time_ns', 0) < since:
        return dict(error='helper event older than this program: that PID folder was already there')
    if e.get('result') == 'allowed-before-exec':
        return None
    return dict(error=e.get('error'), error_type=e.get('error_type'), preexisting=e.get('preexisting'))


def denials(pid, began, ended):
    """Kernel sandbox rows for a failed program's own PID: the reason a reader needs."""
    stamp = lambda t: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t))
    try:
        q = subprocess.run(['/usr/bin/log', 'show', '--style', 'ndjson', '--start', stamp(began - 2), '--end', stamp(ended + 2), '--predicate', '(processIdentifier == 0) AND (eventMessage BEGINSWITH "Sandbox: ") AND (eventMessage CONTAINS "(%d)")' % pid], env=L.SMALL_ENV, capture_output=True, stdin=subprocess.DEVNULL, timeout=max(5, L.time_left(120)))
    except subprocess.TimeoutExpired:
        return dict(log_timed_out=True, rows=[])
    rows = set()
    for line in q.stdout.decode('utf-8', 'replace').splitlines():
        try:
            m = json.loads(line).get('eventMessage', '')
        except ValueError:
            continue
        if ' deny' in m:
            rows.add(re.sub(r'^Sandbox: ', '', m).split('\n')[0][:400])
    return dict(log_exit=q.returncode, rows=sorted(rows))


def guard_gate(plan, pid):
    """The native gate on this program's own log. A missing, linked or unreadable log is a failed gate."""
    try:
        raw = L.read_regular(plan['guard']['log'])
    except OSError as e:
        return ['the guard failed: its log cannot be read: %r' % e], None
    return L.gate_guard(raw.decode('utf-8', 'replace'), [pid])


def run_lane(r, lane, cap, B, rows):
    """Every program, one at a time. A failing test or a helper refusal is a result: the lane goes on. Only a safety reason stops it."""
    O = r / 'state/replay' / (lane + '-runtime')
    O.mkdir(mode=0o700)
    entered = time.monotonic()
    deadline = entered + cap
    results, safety, not_run = [], None, []
    for plan in rows:
        t = plan['target']
        why = safety or L.stopping() or ('lane cap' if time.monotonic() >= deadline - 2 else None)
        if why:
            not_run.append(dict(target=t, why=why))
            continue
        if L.sha(plan['executable']) != plan['executable_sha256'] or L.identity(plan['executable']) != plan['identity']:
            safety = 'executable changed before its run: ' + t
            not_run.append(dict(target=t, why=safety))
            continue
        since = time.time_ns()
        watched = watch(B) if plan['executable'] == B['ssh_watch_target']['path'] else None
        # The real sshd has no PermitUserRC line, so ~/.ssh/rc would run outside any sandbox. Stop before the target.
        if watched is not None and os.path.lexists(B['ssh_rc']):
            safety = '~/.ssh/rc exists: stopped before the sshd target'
            not_run.append(dict(target=t, why=safety))
            continue
        began = time.time()
        row = L.held(plan['argv'], plan['cwd'], plan['environment'], O / (t + '.stdout'), O / (t + '.stderr'), max(1, deadline - time.monotonic()), grace=2, on_start=lambda pid: L.save(O / (t + '-started.json'), dict(pid=pid, target=t, key=plan['binding']['key'])))
        refused = refusal(B, row['pid'], since)
        seen = watch(B) if watched is not None else None
        result = dict(target=t, key=plan['binding']['key'], pid=row['pid'], exit=row['exit'], seconds=row['seconds'], cap=row['cap'], stopped=row['stopped'], helper_refusal=refused, ssh_watch_before=watched, ssh_watch_after=seen, ssh_watch_unchanged=None if watched is None else watched == seen, timed_out=bool(row['stopped']), group_absent=row['group_absent'], survivors=row['survivors'], left_after_kill=row['left_after_kill'], surviving_descendants_cleaned=not row['stopped'] and row['survivor_signaled'], stdout_sha256=L.sha(O / (t + '.stdout')), stderr_sha256=L.sha(O / (t + '.stderr')), executable_identity_unchanged=L.identity(plan['executable']) == plan['identity'], executable_hash_unchanged=L.sha(plan['executable']) == plan['executable_sha256'])
        if row['exit'] != 0 or refused or result['surviving_descendants_cleaned']:
            result['denials'] = denials(row['pid'], began, time.time())
        if plan.get('guard') and not refused:
            guard_fails, result['guard'] = guard_gate(plan, row['pid'])
            result['guard_failures'] = guard_fails
            if guard_fails:
                safety = 'guard, %s: %s' % (plan['binding']['key'], guard_fails[0])
        L.save(O / (t + '-receipt.json'), result)
        results.append(result)
        if not row['group_absent'] or not result['executable_identity_unchanged'] or not result['executable_hash_unchanged'] or result['ssh_watch_unchanged'] is False:
            safety = 'safety stop after ' + t + ': group, executable or ssh watch'
    L.save(O / 'results.json', dict(results=results, not_run=not_run, safety=safety, seconds=round(time.monotonic() - entered, 1)))
    return results, not_run, safety


def age(etime):
    """Seconds from ps etime. A row that does not parse counts as born now, so it can only fail the run."""
    try:
        d, _, t = etime.rpartition('-')
        n = 0
        for x in t.split(':'):
            n = n * 60 + int(x)
        return n + int(d or 0) * 86400
    except ValueError:
        return 0


def processes(r, since):
    """A process whose image sits under the target or source fails the run, and so does an own sshd born after the lane started. An ssh-agent is listed only: launchd can start the owner's own."""
    roots = (str(r / 'target') + '/', str(r / 'source') + '/')
    a = subprocess.run(['/bin/ps', '-axo', 'pid=,ppid=,pgid=,uid=,comm='], env=L.SMALL_ENV, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    b = subprocess.run(['/bin/ps', '-axo', 'pid=,uid=,etime=,ucomm='], env=L.SMALL_ENV, capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
    survivors = [x.strip() for x in a.stdout.decode('utf-8', 'replace').splitlines() if len(x.split(None, 4)) == 5 and x.split(None, 4)[4].startswith(roots)]
    sshd, agents, now = [], [], time.time()
    for line in b.stdout.decode('utf-8', 'replace').splitlines():
        p = line.split(None, 3)
        if len(p) == 4 and p[1] == str(os.getuid()) and now - age(p[2]) >= since - 1:
            name = p[3].strip()
            if name in SSHD_NAMES:
                sshd.append(line.strip())
            elif name == 'ssh-agent':
                agents.append(line.strip())
    return dict(read_ok=a.returncode == 0 and b.returncode == 0, survivors=survivors, own_sshd_born_after_lane_start=sshd, own_ssh_agent_information_only=agents)


# ---- After a lane: did anything change that the plan does not name?
def target_report(r, base):
    T, tmp = str(r / 'target'), str(r / 'target/tmp')
    live, issues = L.tree(T, skip=(tmp,)), []
    for p in sorted(set(base) | set(live)):
        if p.startswith(tmp + '/'):
            continue
        if p not in live or p not in base:
            issues.append(dict(path=p, change='removed' if p not in live else 'new'))
            continue
        d = sorted(k for k in set(base[p]) | set(live[p]) if base[p].get(k) != live[p].get(k))
        if d and not (p == tmp and set(d) <= {'mtime_ns', 'ctime_ns', 'nlink', 'size'}):
            issues.append(dict(path=p, change='changed', fields=d))
    return dict(issues=issues, records=len(live))


def source_report(r, base):
    live, issues = L.tree(r / 'source'), []
    for p in sorted(set(base) | set(live)):
        if p not in live or p not in base:
            issues.append(dict(path=p, change='removed' if p not in live else 'new'))
        elif base[p] != live[p]:
            issues.append(dict(path=p, change='changed', fields=sorted(k for k in base[p] if base[p][k] != live[p].get(k))))
    return dict(issues=issues, records=len(live))


def finite_report(r, remove=False):
    """Only names the helper recorded for a PID it let through, which found nothing there before exec. A name counts as ours only if owned here and born inside that program's own window. No receipt, no claim."""
    rows, me, removed, issues, events, seen = [], os.getuid(), [], [], [], set()
    closed = {}
    for f in (r / 'state/replay').glob('*-runtime/*-receipt.json'):
        closed.setdefault(L.load(f)['pid'], []).append(f.stat().st_mtime)
    for n in sorted(os.listdir(r / 'state/harness-events')):
        f = r / 'state/harness-events' / n / 'event.json'
        if f.is_file() and not f.is_symlink():
            e = L.load(f)
            if e.get('result') == 'allowed-before-exec' and e.get('namespace_patterns') and e.get('preexisting') == []:
                events.append(e)
    with os.scandir('/private/tmp') as it:
        names = [x.name for x in it]
    for e in events:
        for n in names:
            q = '/private/tmp/' + n
            if q in seen or not any(re.search(p, q, re.ASCII | re.IGNORECASE) for p in e['namespace_patterns']):
                continue
            try:
                s = os.lstat(q)
            except FileNotFoundError:
                continue
            seen.add(q)
            own, new = s.st_uid == me, s.st_birthtime >= e['time_ns'] / 1e9 - 1
            ends = closed.get(e['pid'], [])
            inside = any(s.st_birthtime <= t + 2 for t in ends)
            rows.append(dict(path=q, pid=e['pid'], own=own, born_after_admission=new, receipt_seen=bool(ends), born_before_receipt=inside))
            if not (own and new and inside):
                issues.append(dict(path=q, change='finite name not provably ours; left alone'))
            elif remove:
                shutil.rmtree(q) if stat.S_ISDIR(s.st_mode) else os.unlink(q)
                removed.append(q)
    return dict(admissions_with_finite_classes=len(events), leftovers=rows, removed=removed, issues=issues)


def reconcile(r, target_base, source_base, remove=False):
    t, s, f = target_report(r, target_base), source_report(r, source_base), finite_report(r, remove)
    return dict(status='PASS' if not t['issues'] and not s['issues'] and not f['issues'] else 'FAIL', target=t, source=s, finite=f)


def crash_reports(r, before, stems, owner=L.OWNER):
    """New crash reports that bear this step's own program names. Only the two on-purpose SIGQUIT children of larsal_platform pass, and they are named."""
    known, bad = [], []
    for n in sorted(L.diag_names(owner) - before):
        m = L.REPORT_NAME.match(n)
        if not m or m[1] not in stems:
            continue
        child = L.on_purpose_child(owner, n) if m[1].startswith('larsal_platform-') else None
        (known if child else bad).append(dict(report=n, child=child) if child else n)
    return dict(on_purpose_children=known, other_own_reports=bad)


def run(ctx):
    """Returns the step's row. Writes everything under R/r."""
    R, tool = ctx['R'], ctx['tool']
    out = dict(step='rust', reasons=[], safety=None, lanes={}, new_programs=[], seconds={}, withheld_bytes={})
    r = prepare(R, tool)
    dylib = L.guard_dylib(R, tool)
    withheld = ctx.get('withheld', {})
    t0 = time.monotonic()
    toolchain = L.rust_toolchain(r / 'source')
    diag_before = L.diag_names()
    rows, streams = build(r, toolchain)
    L.save(r / 'proof/build/rows.json', rows)
    out['seconds']['build'] = round(time.monotonic() - t0, 1)
    if not all(L.row_clean(x) for x in rows):
        out['reasons'].append('build failed: ' + ', '.join(x['lane'] for x in rows if not L.row_clean(x)))
        return out
    empty_cargo_home(r)
    before = L.tree(r / 'target')
    records, out['seconds']['capture'], after = capture(r, toolchain, streams, before)
    t1 = time.monotonic()
    result, imports = screen(r)
    out['seconds']['import_screen'] = round(time.monotonic() - t1, 1)
    out['import_screen'] = {k: result[k] for k in ('reads', 'refusals', 'tools_equal', 'passed')}
    if not result['passed']:
        out['reasons'].append('import screen refused')
        return out
    out['withheld_bytes'] = byte_withheld(r, tool, records, imports, withheld, streams)
    L.say('rust source paths and byte checks: %d rows withheld' % len(out['withheld_bytes']), sorted(out['withheld_bytes']))
    withheld.update({k: v for k, v in out['withheld_bytes'].items() if k.startswith('needs:')})  # The same dict native reads.
    ledger = {x['path']: x['sha256'] for x in result['ledger']}
    B, binding_sha, out['new_programs'] = materialize(r, tool, records, {**withheld, **out['withheld_bytes']}, dylib, after, ledger)
    custody(B, source_rows=True)
    plans = {lane: check_plan(r, lane, B, binding_sha) for lane in LANES}
    target_base, source_base = L.tree(r / 'target'), L.tree(r / 'source')
    L.save(r / 'proof/target-baseline.json', sorted(target_base.values(), key=lambda x: x['path']))
    L.save(r / 'proof/source-baseline.json', sorted(source_base.values(), key=lambda x: x['path']))
    stems = {x['target'].split('-', 1)[1] for rows_ in plans.values() for x in rows_}
    for lane, cap in RUN_CAPS:
        if out['safety'] or L.stopping():
            out['lanes'][lane] = dict(not_started=out['safety'] or L.stopping())
            out['reasons'].append(lane + ' not started')
            continue
        lane_start, t2 = time.time(), time.monotonic()
        L.check_sealed()
        check_plan(r, lane, B, binding_sha)
        custody(B)
        results, not_run, safety = run_lane(r, lane, cap, B, plans[lane])
        custody(B)
        procs = processes(r, lane_start)
        rec = reconcile(r, target_base, source_base, remove=False)
        L.save(r / 'state/run-lanes' / (lane + '.reconcile.json'), rec)
        reasons = []
        if not_run:
            reasons.append('%d programs not run' % len(not_run))
        if any(x['exit'] != 0 or x['stopped'] or not x['group_absent'] or x['survivors'] for x in results):
            reasons.append('program')
        if any(x['helper_refusal'] for x in results):
            reasons.append('helper refusal')
        if any(x['surviving_descendants_cleaned'] for x in results):
            reasons.append('surviving descendants cleaned')
        reasons += ['guard, %s: %s' % (x['key'], y) for x in results for y in x.get('guard_failures', [])]
        if procs['survivors']:
            reasons.append('surviving process')
        if procs['own_sshd_born_after_lane_start']:
            reasons.append('surviving sshd')
        if not procs['read_ok']:
            reasons.append('process list unreadable')
        if rec['status'] != 'PASS':
            reasons.append('reconcile')
        guarded = [x for x in results if x.get('guard')]
        row = dict(guard=dict(programs=len(guarded), requests=sum(x['guard']['requests'] for x in guarded), loaded=sum(len(x['guard']['loaded_pids']) for x in guarded)), programs=len(results), planned=len(plans[lane]), seconds=round(time.monotonic() - t2, 1), program_seconds=round(sum(x['seconds'] for x in results), 1), reasons=reasons, processes=procs, reconcile=rec['status'], target_records=rec['target']['records'], source_records=rec['source']['records'], finite_leftovers=len(rec['finite']['leftovers']))
        L.save(r / 'state/run-lanes' / (lane + '.json'), row)
        out['lanes'][lane] = row
        out['reasons'] += [lane + ': ' + x for x in reasons]
        if safety or procs['survivors'] or procs['own_sshd_born_after_lane_start']:
            out['safety'] = safety or lane + ': process left'
        L.say('rust lane', lane, row['programs'], 'of', row['planned'], 'seconds', row['seconds'], 'reasons', reasons)
    # The names the helper can prove ours go now, so a later run's PID cannot collide with them.
    last = reconcile(r, target_base, source_base, remove=True)
    L.save(r / 'state/run-lanes/final.reconcile.json', last)
    out['finite_removed'] = len(last['finite']['removed'])
    out['crash_reports'] = crash_reports(r, diag_before, stems)
    if out['crash_reports']['other_own_reports']:
        out['reasons'].append('crash report of an own program: %s' % out['crash_reports']['other_own_reports'])
    return out
