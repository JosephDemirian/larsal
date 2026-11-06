"""Window metadata for the given PIDs only: owner PID, layer, size, on screen. No pixels, no names, no focus change.
Prints a JSON list; empty when none of these PIDs has a window listed."""
import ctypes, json, sys

want = {int(a) for a in sys.argv[1:]}
cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
cg = ctypes.CDLL('/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics')
cf.CFStringCreateWithCString.restype = ctypes.c_void_p
cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
cf.CFArrayGetCount.argtypes = [ctypes.c_void_p]
cf.CFArrayGetCount.restype = ctypes.c_long
cf.CFArrayGetValueAtIndex.argtypes = [ctypes.c_void_p, ctypes.c_long]
cf.CFArrayGetValueAtIndex.restype = ctypes.c_void_p
cf.CFDictionaryGetValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
cf.CFDictionaryGetValue.restype = ctypes.c_void_p
cf.CFNumberGetValue.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
cf.CFBooleanGetValue.argtypes = [ctypes.c_void_p]
cf.CFBooleanGetValue.restype = ctypes.c_ubyte
cg.CGWindowListCopyWindowInfo.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
cg.CGWindowListCopyWindowInfo.restype = ctypes.c_void_p


def key(s): return cf.CFStringCreateWithCString(None, s.encode(), 0x08000100)
def number(d, name, kind=ctypes.c_double, code=13):
    v = cf.CFDictionaryGetValue(d, key(name))
    if not v:
        return None
    out = kind()
    cf.CFNumberGetValue(v, code, ctypes.byref(out))
    return out.value


rows = []
info = cg.CGWindowListCopyWindowInfo(0, 0)  # All windows, on screen or not; the row says which.
if not info:
    print(json.dumps(dict(unavailable=True)))
    sys.exit(0)
for i in range(cf.CFArrayGetCount(info)):
    w = cf.CFArrayGetValueAtIndex(info, i)
    pid = number(w, 'kCGWindowOwnerPID', ctypes.c_int64, 4)
    if int(pid or 0) not in want:
        continue
    on = cf.CFDictionaryGetValue(w, key('kCGWindowIsOnscreen'))
    bounds = cf.CFDictionaryGetValue(w, key('kCGWindowBounds'))
    rows.append(dict(pid=int(pid), layer=number(w, 'kCGWindowLayer', ctypes.c_int64, 4), onscreen=bool(on and cf.CFBooleanGetValue(on)), width=number(bounds, 'Width') if bounds else None, height=number(bounds, 'Height') if bounds else None, alpha=number(w, 'kCGWindowAlpha')))
print(json.dumps(rows))
