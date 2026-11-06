"""The profile generator. The reviewed text with the roots as parameters, plus the stronger Cargo and guard lines listed in README.md."""
import json, re
from pathlib import Path
from gc_lib import NM, OWNER

ROOT_TEXT = re.compile(r'/[A-Za-z0-9/_-]+')


def plain_roots(*roots):
    """A root goes into profile strings and regexes unescaped, so only plain path text is taken."""
    for x in roots:
        assert ROOT_TEXT.fullmatch(x), 'root text a profile cannot hold: %r' % (x,)


def holds_board(profile_text):
    """Does this profile open the pasteboard or the window server? Such a row loads the guard."""
    return PASTEBOARD in profile_text or WINDOW in profile_text

OLD_MACH = ('(deny mach-lookup (global-name "com.apple.pboard") (global-name "com.apple.SecurityAgent") (global-name "com.apple.securityd") (global-name "com.apple.secd") (global-name "com.openssh.ssh-agent") (global-name "com.apple.sshd") (global-name "com.apple.CoreAuthentication.daemon") (global-name "com.apple.biometrickitd") (global-name "com.apple.ctkd"))\n'
            '(deny mach-lookup (global-name "com.apple.cfprefsd.agent") (global-name "com.apple.WindowServer") (global-name-prefix "com.apple.tccd"))\n')
PREFIXES = ['com.apple.pasteboard', 'com.apple.pboard', 'com.apple.windowserver', 'com.apple.CARenderServer', 'com.apple.SecurityServer', 'com.apple.securityd', 'com.apple.secd', 'com.apple.security.agent', 'com.apple.security.authhost', 'com.apple.ctkd', 'com.apple.coreservices.launchservicesd', 'com.apple.coreservices.quarantine-resolver', 'com.apple.lsd', 'com.apple.runningboard',
            'com.apple.CoreAuthentication', 'com.apple.LocalAuthentication', 'com.apple.coreservices.appleevents', 'com.apple.coreservices.uasharedpasteboard', 'com.apple.coreservices.uauseractivitypasteboard', 'com.apple.tsm.uiserver', 'com.apple.dock.server', 'com.apple.security.KeychainStasher', 'com.apple.security.XPCKeychainSandboxCheck', 'com.apple.security.cloudkeychainproxy3', 'com.apple.keychainsharingmessagingd',
            'com.apple.replayd', 'com.apple.screencaptureui', 'com.apple.screensharing.agent', 'com.apple.authd', 'com.apple.security.authtrampoline', 'com.apple.security.octagon', 'com.apple.security.kcsharing', 'com.apple.iohideventsystem']
REAL_MACH = '(deny mach-lookup ' + ' '.join('(global-name-prefix "%s")' % x for x in PREFIXES) + ')\n(deny appleevent-send)\n'
HOME_LINES = ('(deny network*)\n(deny file-read* (subpath "{o}"))\n'
              '(allow file-read* (subpath "{o}/.rustup") (subpath "{o}/.cargo/bin"))\n'
              '(deny file-read* (subpath "/Library/Keychains") (subpath "/System/Library/Keychains") (subpath "/private/var/db/Keychains"))\n')
LOCAL = '(allow network-inbound (local ip "localhost:*"))\n(allow network-outbound (remote ip "localhost:*"))\n'
PTY = '(allow file-write-data (literal "/dev/ptmx") (regex #"^/dev/ttys[0-9][0-9][0-9]$"))\n'
PASTEBOARD = '(allow mach-lookup (global-name "com.apple.pasteboard.1"))\n'
WINDOW = '(allow mach-lookup (global-name "com.apple.windowserver.active"))\n'
KEY = '(allow mach-lookup (global-name "com.apple.SecurityServer"))\n'
# own_agent only: the real sshd calls sandbox_init itself, and the kernel refuses a second, different sandbox. Exactly that image leaves.
SSHD = '(allow process-exec (with no-sandbox) (literal "/usr/sbin/sshd"))\n(allow signal (target children))\n'


def rust_profiles(root, owner=OWNER):
    """The R2b family. root holds source, target, run, tmp, home, cache."""
    plain_roots(root, owner)
    prop, target, source = root + '/run', root + '/target', root + '/source'

    def writes(roots):
        return ' '.join('(subpath "%s")' % r for r in roots)

    def head(roots):
        return ('(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* %s (literal "/dev/null"))\n' % writes(roots)
                + HOME_LINES.format(o=owner) + OLD_MACH + REAL_MACH + '(deny iokit*)\n'
                + '(deny file-write* (subpath "%s"))\n(deny file-write* (subpath "%s"))\n' % (source, target))

    def signals(same=True):
        return '(deny signal)\n(allow signal (target self))\n' + ('(allow signal (target same-sandbox))\n' if same else '')

    def links(sub):
        return '(deny file-link)\n' + ''.join('(allow file-link (subpath "%s"))\n' % s for s in sub)

    def unix(path):
        return ('(allow network-bind network-inbound (local unix-socket (path-regex #"^%s($|/)")))\n' % path
                + '(allow network-outbound (remote unix-socket (path-regex #"^%s($|/)")))\n' % path)

    def cargo(extra):
        roots = [target, root + '/cargo-home', prop + '/env/runtime', prop + '/tmp', prop + '/instance'] + extra
        return ('(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* %s (literal "/dev/null"))\n' % writes(roots)
                + HOME_LINES.format(o=owner) + OLD_MACH + REAL_MACH + '(deny iokit*)\n(deny file-write* (subpath "%s"))\n' % source
                + links([target]) + signals())

    tmp, inst, rt = prop + '/tmp', prop + '/instance', prop + '/env/runtime'
    base = head([rt, tmp, inst]) + links([tmp]) + signals() + LOCAL + unix(tmp) + unix(inst)
    target_tmp = '(allow file-write* (subpath "%s/tmp"))\n' % target
    return {
        'build-cargo.sb': cargo([]),
        'capture-cargo.sb': cargo([root + '/state/capture']),
        'harness-runtime-base.sb': base,
        'harness-runtime-target-tmp.sb': base + target_tmp,
        'harness-runtime-target-tmp-sshd.sb': base + target_tmp + SSHD,
        'cli-runtime.sb': base + PTY + PASTEBOARD,
        'pty-runtime.sb': base + PTY + PASTEBOARD + WINDOW + KEY,
        'harness-runtime-key.sb': base + KEY,
        'harness-runtime-pasteboard-key.sb': base + PASTEBOARD + KEY,
        'harness-runtime-pasteboard.sb': base + PASTEBOARD,
        'harness-runtime-pasteboard-target-tmp.sb': base + PASTEBOARD + target_tmp,
        'import-admit.sb': head([root + '/tmp', root + '/home', root + '/cache']) + links([]) + signals(False) + '(deny process-exec)\n(allow process-exec (literal "%s"))\n' % NM,
    }


GUARD_NAMES = ['com.apple.pboard', 'com.apple.SecurityAgent', 'com.apple.securityd', 'com.apple.secd', 'com.openssh.ssh-agent', 'com.apple.sshd', 'com.apple.CoreAuthentication.daemon', 'com.apple.biometrickitd', 'com.apple.ctkd', 'com.apple.cfprefsd.agent', 'com.apple.WindowServer']
GUARD_PREFIXES = PREFIXES + ['com.apple.tccd']


def guard_profiles(root, owner=OWNER):
    """The G59 outer guard for the static, doc and fuzz lanes: guard.sb, the audit line, the one index copy."""
    plain_roots(root, owner)
    guard = '\n'.join([
        '(version 1)', '(allow default)', '(deny file-write*)',
        '(allow file-write* (subpath "%s") (literal "/dev/null"))' % root,
        '(deny network*)', '(deny file-read* (subpath "%s"))' % owner,
        '(allow file-read* (subpath "{o}/.rustup") (subpath "{o}/.cargo/bin"))'.format(o=owner),
        '(allow file-read* (literal "%s/.local/share/swiftlint/0.65.1/swiftlint"))' % owner,
        '(allow file-read* (subpath "{o}/.cargo/advisory-db") (subpath "{o}/.cargo/advisory-dbs"))'.format(o=owner),
        '(deny file-read* (subpath "/Library/Keychains") (subpath "/System/Library/Keychains") (subpath "/private/var/db/Keychains"))',
        '(deny mach-lookup ' + ' '.join('(global-name "%s")' % n for n in GUARD_NAMES) + ')',
        '(deny mach-lookup ' + ' '.join('(global-name-prefix "%s")' % n for n in GUARD_PREFIXES) + ')',
        '(deny appleevent-send)', '(deny iokit*)', '(deny signal)', '(allow signal (target self))', '(allow signal (target same-sandbox))', ''])
    return {
        'guard.sb': guard,
        # cargo-audit canonicalizes its own path; listing those folders stays denied.
        'guard-audit.sb': guard + '(allow file-read-metadata (literal "/Users") (literal "{o}") (literal "{o}/.cargo"))\n'.format(o=owner),
        # One copy command only: the public crates.io index cache into the private Cargo home.
        'guard-copy-index.sb': guard + '(allow file-read* (subpath "%s/.cargo/registry/index"))\n' % owner,
    }


def export_profile(e, owner=OWNER):
    """The export: its one write root is the export folder. It reads the repository, so the owner's home stays readable except the secrets; git runs under it."""
    plain_roots(e, owner)
    return ('(version 1)\n(allow default)\n(deny file-write*)\n(allow file-write* (subpath "%s") (literal "/dev/null"))\n' % e
            + '(deny network*)\n(deny file-read* (subpath "{o}/.ssh") (subpath "{o}/Library") (subpath "/Library/Keychains") (subpath "/System/Library/Keychains") (subpath "/private/var/db/Keychains"))\n'.format(o=owner)
            + OLD_MACH + REAL_MACH + '(deny iokit*)\n(deny signal)\n(allow signal (target self))\n(allow signal (target same-sandbox))\n')


GRANTED = 'file-write-create file-write-data file-write-unlink'
KEEP = ('s', 'home', 'tmp', 'cache', 'instance', 'modules', 'compiler-tmp', 'lane-out')
HEAD_END = '(allow file-write* (literal "/dev/null"))\n'


def deny_lines(rule):
    return '(deny file-write* ' + rule + ')\n(deny ' + GRANTED + ' ' + rule + ')\n'


def native_needs(tool, r, t, withheld=()):
    """The needs rows that still hold their grant. A row whose pin or byte check failed is left out: base has no such line."""
    out = []
    for n in json.loads(Path(tool, 'tables/needs.json').read_bytes()):
        if 'needs:' + n['id'] not in withheld:
            out.append(dict(n, line=n['line'].replace('{R}', r).replace('{T}', t)))
    return out


def native_profile(tool, r, t, owner=OWNER, withheld=()):
    """The N1b composition: base, controls, link, grants, needs. Base and controls are the reviewed text with the roots as parameters."""
    plain_roots(r, t, owner)
    assert r.startswith('/private/tmp/') and t.startswith('/private/var/folders/')
    base = Path(tool, 'native-base.sb').read_text().replace('{R_TMP}', r[len('/private'):]).replace('{R}', r).replace('{T_VAR}', t[len('/private'):]).replace('{T}', t).replace('{OWNER}', owner)
    controls = Path(tool, 'native-controls.sb').read_text()
    assert 'job-creation' not in base + controls and base.count(HEAD_END) == 1
    assert base.count('(allow (with report) file-write* (regex') == 2
    base = base.replace('(allow (with report) file-write* (regex', '(allow (with report) ' + GRANTED + ' (regex')
    # The writable root narrowed at once to the working folders, so no tool can change the driver, the profile, a run's evidence or the other lanes' roots.
    keep = ' '.join('(require-not (subpath "%s/%s"))' % (r, n) for n in KEEP)
    base = base.replace(HEAD_END, HEAD_END + '(deny file-write* (require-all (subpath "%s") %s))\n' % (r, keep))
    # The owner's home is closed except the toolchain. Same two lines an earlier cargo lane ran with.
    home = '(deny file-read* (subpath "{o}"))\n(allow file-read* (subpath "{o}/.rustup") (subpath "{o}/.cargo/bin"))\n'.format(o=owner)
    keychains = '(deny file-read* (subpath "{o}/Library") (subpath "{o}/.ssh")'.format(o=owner)
    assert base.count(keychains) == 1
    base = base.replace(keychains, home + keychains)
    link = ''.join('(allow file-link (subpath "%s/%s"))\n' % (r, n) for n in KEEP)
    grants = ('(allow (with report) file-write-create file-write-unlink (require-all (vnode-type DIRECTORY) (regex #"^' + t + '/ibtoold-[0-9]+$")))\n'
              + '(allow (with report) ' + GRANTED + ' (regex #"^' + t + '/ibtoold-[0-9]+/"))\n'
              + '(allow (with report) ' + GRANTED + ' (regex #"^' + t + '/Untitled-' + '[A-Za-z0-9]' * 8 + r'\.uicatalog(-journal)?$"))' + '\n')
    added = ''.join('; need: ' + n['who'] + '\n' + n['line'].rstrip('\n') + '\n' for n in native_needs(tool, r, t, withheld))
    return base + controls + link + grants + added
