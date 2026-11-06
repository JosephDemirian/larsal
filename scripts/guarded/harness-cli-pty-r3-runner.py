#!/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python -B -S
import hashlib, json, os, pathlib, re, stat, subprocess, sys, time

HERE = pathlib.Path(__file__).resolve().parent
NM = '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-nm'
SANDBOX = '/usr/bin/sandbox-exec'
CLASSES = {
    'bridge': ['larsal-bridge-{pid}-[0-9]+'],
    'browser_setup': ['larsal-e7s6-{pid}-[0-9]+'],
    'browser_int': ['larsal-browser-{pid}-[0-9]+', 'larsal-browser-{pid}-w[0-9]+'],
    'browser_unit': ['larsal-browser-t14-other-{pid}', 'larsal-browser-t14-same-{pid}'],
    'ssh_unit': ['e9s2u-{pid}-wait', 'e9s2u-{pid}-silent'],
    'ssh_agent': ['e9s1-{pid}-'+tag+'[0-9]+' for tag in ['a', 'f', 't26', 't27', 't37', 't68', 'f109']],
    'ssh_own': ['e9s1-{pid}-'+tag+'[0-9]+' for tag in ['a', 'f', 'o', 't11', 't14', 't39', 'ld213', 'w', 't52', 't57', 'ld203', 'sshd']],
    'ssh_ffi': ['e9s1-{pid}-'+tag+'[0-9]+' for tag in ['a', 'f', 'o', 'l', 'c', 'h', 'w', 'q', 'n', 't', 'k', 'r', 'ds', 'do', 'dt', 'pf', 'pv']],
    'session': ['larsal-session-{pid}-[0-9]+'],
    'ffi_browser': ['larsal-ffi-e7s6-{pid}'],
    'ffi_safari': ['larsal-ffi-e7s6-safari-{pid}'],
    'ffi_switch': ['larsal-ffi-e7s6-switch-{pid}'],
    'ffi_start': ['larsal-ffi-e7s6-start-{pid}'],
    'ffi_rewrite': ['larsal-ffi-e7s6-rewrite-{pid}'],
    'ffi_group': ['larsal-ffi-e7s6-group-{pid}'],
}

def patterns(classes, pid):
    if len(classes) != len(set(classes)) or any(c not in CLASSES for c in classes):
        raise ValueError('invalid finite namespace class')
    return ['^/private/tmp/'+part.format(pid=pid)+'($|/)' for c in classes for part in CLASSES[c]]

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def identity(path):
    s = path.stat()
    return dict(device=s.st_dev, inode=s.st_ino, size=s.st_size, mode=stat.S_IMODE(s.st_mode),
                mtime_ns=s.st_mtime_ns, uid=s.st_uid)

def owned(path, directory=False):
    s = path.lstat()
    if s.st_uid != os.getuid() or s.st_mode & 0o022 or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise ValueError('not an owned regular '+('directory' if directory else 'file'))
    return path

def absolute(value):
    if not isinstance(value, str) or not os.path.isabs(value) or '..' in pathlib.Path(value).parts:
        raise ValueError('invalid absolute path')
    return pathlib.Path(value).resolve(strict=True)

def within(path, root):
    path.relative_to(root)
    return path

def private(value, directory=False):
    path = within(absolute(value), HERE)
    owned(HERE, True)
    for parent in reversed(path.parents):
        if parent != HERE and HERE in parent.parents:
            owned(parent, True)
    return owned(path, directory)

def occupied(regexes):
    return sorted('/private/tmp/'+entry.name for entry in os.scandir('/private/tmp')
                  if any(re.search(p, '/private/tmp/'+entry.name, re.ASCII | re.IGNORECASE) for p in regexes))

def main():
    os.umask(0o077)
    event = dict(pid=os.getpid(), argv=sys.argv[1:], result='rejected', time_ns=time.time_ns())
    folder = None
    try:
        helper = owned(pathlib.Path(__file__).resolve(strict=True))
        event['helper_sha256'] = sha(helper)
        if event['helper_sha256'] != os.environ['LARSAL_HARNESS_RUNNER_SHA256']:
            raise ValueError('helper pin mismatch')
        config_path = private(str(HERE/'runner-cli-pty-r3-config.json'))
        event['config_sha256'] = sha(config_path)
        if event['config_sha256'] != os.environ['LARSAL_HARNESS_CONFIG_SHA256']:
            raise ValueError('config pin mismatch')
        config = json.loads(config_path.read_bytes())
        if config['version'] != 1 or absolute(config['fixture_root']) != HERE:
            raise ValueError('configuration fixture mismatch')
        source = private(config['source_manifest'])
        event['source_manifest_sha256'] = sha(source)
        if event['source_manifest_sha256'] != config['source_manifest_sha256']:
            raise ValueError('source manifest pin mismatch')
        admissions = private(config['admissions'])
        event['admissions_sha256'] = sha(admissions)
        if event['admissions_sha256'] != config['admissions_sha256']:
            raise ValueError('admission pin mismatch')
        admitted = json.loads(admissions.read_bytes())
        if admitted['version'] != 1 or admitted['source_manifest_sha256'] != event['source_manifest_sha256']:
            raise ValueError('admission source mismatch')
        roots = [owned(absolute(p), True) for p in config['artifact_roots']]
        audit = private(config['audit_dir'], True)
        candidate = audit/str(os.getpid())
        candidate.mkdir(mode=0o700)
        folder = candidate
        if len(sys.argv) < 2:
            raise ValueError('missing executable')
        binary = owned(absolute(sys.argv[1]))
        if not any(binary != root and root in binary.parents for root in roots):
            raise ValueError('executable outside artifact roots')
        if not os.access(binary, os.X_OK):
            raise ValueError('not executable')
        matches = [a for a in admitted['artifacts'] if a['path'] == str(binary)]
        if len(matches) != 1:
            raise ValueError('executable not uniquely admitted')
        admission = matches[0]
        event.update(realpath=str(binary), identity=identity(binary), executable_sha256=sha(binary),
                     classes=admission['classes'], admission=admission['binding'], args=sys.argv[2:])
        if event['executable_sha256'] != admission['sha256'] or event['identity'] != admission['identity']:
            raise ValueError('executable identity/hash mismatch')
        regexes = patterns(admission['classes'], os.getpid())
        event['namespace_patterns'] = regexes
        event['preexisting'] = occupied(regexes)
        if event['preexisting']:
            raise ValueError('occupied PID namespace')
        for tool, key in [(NM, 'nm_sha256'), (SANDBOX, 'sandbox_sha256')]:
            if sha(pathlib.Path(tool)) != config[key]:
                raise ValueError('installed tool pin mismatch')
        event['nm_command'] = [NM, '-u', str(binary)]
        result = subprocess.run(event['nm_command'], capture_output=True, timeout=30, check=False)
        (folder/'nm.stdout').write_bytes(result.stdout)
        (folder/'nm.stderr').write_bytes(result.stderr)
        event.update(nm_exit=result.returncode, nm_stdout_sha256=sha(folder/'nm.stdout'),
                     nm_stderr_sha256=sha(folder/'nm.stderr'))
        result.check_returncode()
        if result.stderr:
            raise ValueError('unexpected nm stderr')
        symbols = [line.strip() for line in result.stdout.decode('utf-8', errors='strict').splitlines() if line.strip()]
        if not symbols or any(re.fullmatch(r'[A-Za-z_.$][A-Za-z0-9_.$]*', s) is None for s in symbols):
            raise ValueError('unrecognized nm output')
        event['forbidden_imports'] = [s for s in symbols if re.search(r'_Sec(?:Item|Keychain|AccessControl)', s)]
        if event['forbidden_imports']:
            raise ValueError('forbidden Security import')
        if 'runtime_base' in admission:
            selected_base = admission['runtime_base']
            config = dict(config, runtime_base=selected_base['path'], runtime_base_sha256=selected_base['sha256'])
        base = private(config['runtime_base'])
        if sha(base) != config['runtime_base_sha256']:
            raise ValueError('runtime base pin mismatch')
        profile = folder/'runtime.sb'
        if occupied(regexes):
            raise ValueError('PID namespace became occupied')
        with profile.open('x') as stream:
            stream.write(base.read_text())
            for pattern in regexes:
                stream.write('(allow file-write* (regex #'+json.dumps(pattern)+'))\n')
                stream.write('(allow network-bind network-inbound (local unix-socket (path-regex #'+json.dumps(pattern)+')))\n')
                stream.write('(allow network-outbound (remote unix-socket (path-regex #'+json.dumps(pattern)+')))\n')
        event.update(profile=str(profile), profile_sha256=sha(profile), runtime_base_sha256=sha(base),
                     exec_argv=[str(binary), *sys.argv[2:]], result='allowed-before-exec')
        with (folder/'event.json').open('x') as stream:
            json.dump(event, stream, sort_keys=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        if identity(binary) != event['identity'] or sha(binary) != event['executable_sha256']:
            raise ValueError('executable changed immediately before exec')
        if occupied(regexes) or sha(helper) != event['helper_sha256'] or sha(config_path) != event['config_sha256'] or sha(admissions) != event['admissions_sha256'] or sha(profile) != event['profile_sha256']:
            raise ValueError('binding changed immediately before exec')
        # shortcut: pathname exec needs quiescent owned artifacts; revisit if concurrent writers are admitted.
        argv = event['exec_argv']
        if 'guard' in admission:
            # dyld drops DYLD_* for the protected sandbox-exec, so env sets it inside the sandbox, right before the test program. The PID stays the same.
            guard = admission['guard']
            if sha(pathlib.Path(guard['path'])) != guard['sha256']:
                raise ValueError('guard library pin mismatch')
            argv = ['/usr/bin/env', 'DYLD_INSERT_LIBRARIES='+guard['path'], 'LARSAL_GUARD_LOG='+guard['log'], *argv]
        os.execv(SANDBOX, [SANDBOX, '-f', str(profile), *argv])
    except Exception as error:
        event.update(result='rejected', error_type=type(error).__name__, error=str(error))
        if folder is not None and folder.is_dir():
            (folder/'event.json').write_text(json.dumps(event, sort_keys=True, indent=2)+'\n')
        print('harness runner: '+json.dumps(event, sort_keys=True), file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
