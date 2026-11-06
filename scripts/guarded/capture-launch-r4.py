#!/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/Resources/Python.app/Contents/MacOS/Python -B -S
import json, os, pathlib, stat, sys, time

os.umask(0o077)
path = pathlib.Path(os.environ['LARSAL_CAPTURE_LAUNCH_DIR'])/(str(os.getpid())+'.json')
parent = path.parent.resolve(strict=True)
info = parent.stat()
if not path.is_absolute() or path.parent != parent or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or len(sys.argv) < 2:
    raise ValueError('capture requires an owned private absolute output and executable argv')
record = dict(stage='discovery-only', payload_executed=False, pid=os.getpid(),
              time_ns=time.time_ns(), argv=sys.argv[1:], cwd=os.getcwd(), environment=dict(os.environ))
with path.open('x') as stream:
    json.dump(record, stream, sort_keys=True, indent=2)
    stream.write('\n')
    stream.flush()
    os.fsync(stream.fileno())
# Discovery must never be mistaken for a successful payload run.
sys.exit(78)
