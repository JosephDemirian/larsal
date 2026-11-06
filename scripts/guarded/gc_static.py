"""The static, doc and fuzz lanes, in check.sh's own bodies under the G59 outer guard."""
import os, shlex, shutil, subprocess
from pathlib import Path
import gc_lib as L
import gc_pins, gc_profiles

CAPS = dict(g1=1500, deny=240, audit=240, docs=900, fuzz=1200)


def env_for(g):
    tc, dev = L.TC, L.XCODE
    return dict(
        HOME=g + '/home', CFFIXED_USER_HOME=g + '/home', TMPDIR=g + '/tmp/', XDG_CACHE_HOME=g + '/cache', XDG_CONFIG_HOME=g + '/env/config', XDG_DATA_HOME=g + '/env/data',
        RUSTUP_HOME=L.OWNER + '/.rustup', RUSTUP_AUTO_INSTALL='0', PATH=':'.join([tc, dev + '/usr/bin', L.OWNER + '/.cargo/bin', '/usr/bin', '/bin', '/usr/sbin', '/sbin']),
        PYTHONDONTWRITEBYTECODE='1', PYTHONNOUSERSITE='1', CARGO_HOME=g + '/cargo-home', CARGO_TARGET_DIR=g + '/target', CARGO_NET_OFFLINE='true', CARGO_BUILD_JOBS='4',
        DEVELOPER_DIR=dev, SDKROOT=dev + '/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk', CC=tc + '/clang', CXX=tc + '/clang++', AR=tc + '/ar', RANLIB=tc + '/ranlib',
        CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=tc + '/clang', CLANG_MODULE_CACHE_PATH=g + '/env/modules', SWIFT_MODULECACHE_PATH=g + '/env/swift-modules',
        LARSAL_TEST_HIDDEN='1', LARSAL_TEST_INSTANCE_DIR=g + '/instance', SSH_AUTH_SOCK=g + '/instance/no-owner-ssh.sock')


def body(source, tool, logs, steps):
    """check.sh's text, up to its first gate line, only if it equals the route table. Three asserted changes: logs outside the source, the row per step in the tail, SwiftLint's cache off."""
    text = L.read_regular(Path(source, 'scripts/check.sh')).decode('utf-8', 'strict')
    bad = gc_pins.check_sh_failures(text, tool)
    if bad:
        raise L.Custody(bad[0])
    text = text[:text.index('\ngate "G1 static" g1\n') + 1]
    for old, new in (('LOGS=target/check\n', 'LOGS=%s\nGC_STEPS=%s\n' % (shlex.quote(logs), shlex.quote(steps))),
                     ('"$bin" lint --strict --quiet)', '"$bin" lint --strict --quiet --no-cache)')):
        assert text.count(old) == 1, old
        text = text.replace(old, new)
    return text + L.read_regular(L.sealed(Path(tool, 'check-tail.sh'))).decode('utf-8', 'strict')


def prepare(R, tool):
    g = R / 'g'
    if g.exists():
        return g
    L.mkdirs(g, *[g / d for d in ('home', 'tmp', 'cache', 'env/config', 'env/data', 'env/modules', 'env/swift-modules', 'cargo-home', 'target', 'instance', 'logs/artifacts')])
    # Outside the guard's write root, read only, compared before every use: a lane cannot rewrite what confines the next one.
    P = R / 'guard-profiles'
    P.mkdir(mode=0o700)
    for n, t in gc_profiles.guard_profiles(str(g)).items():
        L.seal_file(P / n, t.encode())
    os.chmod(P, 0o500)
    subprocess.run(['/bin/cp', '-cRp', str(R / 'e'), str(g / 'source')], check=True, env=L.SMALL_ENV)
    os.chmod(g / 'source', 0o700)
    # One read outside the guard, as the native setup: the pinned SwiftLint binary, copied so the guard keeps the owner's home closed.
    lint = Path(L.swiftlint_path(g / 'source', str(g / 'home')))
    L.mkdirs(lint.parent)
    shutil.copyfile(L.swiftlint_path(g / 'source', L.OWNER), lint)
    lint.chmod(0o755)
    return g


def phase(g, tool, name, profile='guard.sb', cap=None):
    gs = str(g)
    L.check_sealed()
    assert not [p for p in L.absent_configs(g / 'source', g / 'cargo-home') if os.path.lexists(p)], 'Cargo config files outside the source'
    # The route is read from the export, which no lane can write.
    script = body(g.parent / 'e', tool, gs + '/logs/artifacts', gs + '/logs/steps.tsv')
    row = L.held([L.SANDBOX, '-f', L.sealed(g.parent / 'guard-profiles' / profile), '/bin/bash', '-c', script, str(g / 'source/scripts/check.sh'), name], g / 'source', dict(env_for(gs), FUZZ_SECONDS='30'), g / 'logs' / (name + '.stdout'), g / 'logs' / (name + '.stderr'), L.time_left(cap or CAPS[name]))
    row['phase'], row['profile'] = name, profile
    L.say('phase', name, 'exit', row['exit'], 'seconds', row['seconds'])
    return row


def copy_advisory_data(g):
    """Public advisory data into the private Cargo home, under the guard; then the public index cache by its own one-copy profile. No fetch."""
    gs, c = str(g), L.OWNER + '/.cargo'
    env = env_for(gs)
    rows = []
    for n, profile, argv in (('copy-advisory', 'guard.sb', ['/bin/cp', '-R', c + '/advisory-db', c + '/advisory-dbs', gs + '/cargo-home/']),
                             ('copy-index-folder', 'guard.sb', ['/bin/mkdir', '-p', gs + '/cargo-home/registry']),
                             ('copy-index', 'guard-copy-index.sb', ['/bin/cp', '-R', c + '/registry/index', gs + '/cargo-home/registry/'])):
        L.check_sealed()
        row = L.held([L.SANDBOX, '-f', L.sealed(g.parent / 'guard-profiles' / profile)] + argv, g, env, g / 'logs' / (n + '.stdout'), g / 'logs' / (n + '.stderr'), L.time_left(120))
        row['phase'], row['profile'] = n, profile
        rows.append(row)
    return rows


def write_rows(step, rows):
    return dict(step=step, phases=rows, reasons=[x['phase'] + ' exit %s%s' % (x['exit'], ' stopped: ' + x['stopped'] if x['stopped'] else '') for x in rows if not L.row_clean(x)])


def run_static(ctx):
    R, tool = ctx['R'], ctx['tool']
    g = prepare(R, tool)
    rows = [phase(g, tool, 'g1')]
    rows += copy_advisory_data(g)
    rows.append(phase(g, tool, 'deny'))
    rows.append(phase(g, tool, 'audit', 'guard-audit.sb'))
    return write_rows('static', rows)


def run_docs(ctx):
    g = prepare(ctx['R'], ctx['tool'])
    return write_rows('docs', [phase(g, ctx['tool'], 'docs')])


def run_fuzz(ctx):
    g = prepare(ctx['R'], ctx['tool'])
    return write_rows('fuzz', [phase(g, ctx['tool'], 'fuzz')])
