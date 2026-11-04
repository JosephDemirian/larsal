"""The channel's known answers in WebCrypto (story E7-S1; INT-01.50, T79).

Larsal's side computes the same values in larsal-crypto (crates/larsal-crypto/src/bridge.rs,
t78_* and t79_channel_vectors_cv1_to_cv9); both must give INT-01.50's bytes. Runs in
the installed Chrome, headless, in the driver's demo extension (service worker),
through E7-S7b's driver only (INT-11.43).

Run: python3 -I extension/test/test_channel_vectors.py
Needs /Applications/Google Chrome.app and Xcode's swiftc. No window, no network,
nothing outside /tmp (AGENTS.md rules 7, 10, 11).
"""

import os
import sys
import time
import unittest

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import driver  # noqa: E402

DEMO = os.path.join(driver.HERE, "demo-extension")

# INT-01.50: RFC 7748 section 6.1 (c = Alice, a = Bob), the identification key i,
# the nonces N1 and N2, the contents P1 and P2.
C_SECRET = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
A_SECRET = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
I_SECRET = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
P1 = '{"type":"status","req":1}'
P2 = '{"type":"status","req":1,"vaults":[]}'

EXPECTED = {
    "C": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "A": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "Z": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    "Z_back": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    "CV2": "e4b77f9fa8df1e045efa982b7a70fe6194b4cdb32153a5c034d80a5d63ec1e74",
    "CV3": "999ff990adb5b4328ba790203c0e5e09e22b7cc989d2ba515754f70922b20da7",
    "CV4": "5c843e032bda41a65a5cbe0903401ab186ef872add0a69ee862fa035dbe679eeaf1de73c93cafc6e7f",
    "CV5": "d58bf61c8472d102d307203c8a89d13e5d8205fd0ad99803d18551dd97216027aa9eae11a9e2f08823592d7c41c7703f78a589837a",
    "CV6": "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f",
    "CV7": "d0bda120f120bed6b1c132f737ab678e1a4358c0984a617d2fe14f665460932f",
    "CV7_back": "d0bda120f120bed6b1c132f737ab678e1a4358c0984a617d2fe14f665460932f",
    "CV8": "2bb001852cfa20c1028578b07956ef04efa252c1d2659bae42fac46c5a3be859",
    "CV9": "3206e2599b88ce227a7a9a6a09d2b52e7279593b2a02c502b476917c592ead05e1440ebc6f879ac3fba856cd6c3e8652",
    # INT-11.7's own path (non-extractable keys, deriveKey straight from X25519) gives CV-4,
    # opens CV-5, and seals the proof as CV-9.
    "CV4_by_derive_key": "5c843e032bda41a65a5cbe0903401ab186ef872add0a69ee862fa035dbe679eeaf1de73c93cafc6e7f",
    "CV5_opened_by_derive_key": P2.encode().hex(),
    "CV9_by_derive_key": "3206e2599b88ce227a7a9a6a09d2b52e7279593b2a02c502b476917c592ead05e1440ebc6f879ac3fba856cd6c3e8652",
    # The published vectors (HKDF: OKM only, WebCrypto gives no PRK).
    "HKDF_A1": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    "HKDF_A2": "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
    "HKDF_A3": "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    "GCM_G1": "bdc1ac884d332457a1d2664f168c76f0",
    "GCM_G2": "fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489",
    "GCM_G3": "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8bc95c532fecc594c36d1550286a7a3f0",
}

SCRIPT = r"""(async () => {
  const s = crypto.subtle;
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const bytes = (h) => new Uint8Array(h.match(/../g).map((x) => parseInt(x, 16)));
  const seq = (from, to) => { const a = []; for (let x = from; x <= to; x++) a.push(x); return new Uint8Array(a); };
  const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0;
    for (const p of parts) { out.set(p, i); i += p.length; } return out; };
  const text = (t) => new TextEncoder().encode(t);
  // RFC 8410 PKCS #8 for an X25519 private key: the fixed prefix, then the 32 bytes.
  const pkcs8 = (h) => cat(bytes('302e020100300506032b656e04220420'), bytes(h));
  const X = { name: 'X25519' };
  const priv = (h) => s.importKey('pkcs8', pkcs8(h), X, true, ['deriveBits', 'deriveKey']);
  const pub = async (k) => { const j = await s.exportKey('jwk', k);
    return Uint8Array.from(atob(j.x.replace(/-/g, '+').replace(/_/g, '/')), (ch) => ch.charCodeAt(0)); };
  const raw = (b) => s.importKey('raw', b, X, true, []);
  const dh = async (k, b) => new Uint8Array(await s.deriveBits({ name: 'X25519', public: await raw(b) }, k, 256));
  const hkdf = async (ikm, salt, info, bits) => new Uint8Array(await s.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info }, await s.importKey('raw', ikm, 'HKDF', false, ['deriveBits']), bits));
  const gcm = async (key, iv, pt, aad) => new Uint8Array(await s.encrypt(
    aad ? { name: 'AES-GCM', iv, additionalData: aad } : { name: 'AES-GCM', iv },
    await s.importKey('raw', key, 'AES-GCM', false, ['encrypt']), pt));
  const empty = new Uint8Array(0);
  const N1 = bytes('000000000000000000000001'), N2 = bytes('000000000000000000000002');
  const [c, a, i] = [await priv('%(c)s'), await priv('%(a)s'), await priv('%(i)s')];
  const [C, A, I] = [await pub(c), await pub(a), await pub(i)];
  const r = { C: hex(C), A: hex(A) };
  const Z = await dh(c, A);
  r.Z = hex(Z); r.Z_back = hex(await dh(a, C));
  const request = await hkdf(Z, empty, cat(text('browser-bridge request key v1'), C, A), 256);
  const reply = await hkdf(Z, empty, cat(text('browser-bridge reply key v1'), C, A), 256);
  r.CV2 = hex(request); r.CV3 = hex(reply);
  r.CV4 = hex(await gcm(request, N1, text('%(p1)s')));
  r.CV5 = hex(await gcm(reply, N1, text('%(p2)s')));
  r.CV6 = hex(I);
  const Zid = await dh(i, A);
  r.CV7 = hex(Zid); r.CV7_back = hex(await dh(a, I));
  const proof = await hkdf(Zid, empty, cat(text('browser-bridge proof key v1'), C, A, I), 256);
  r.CV8 = hex(proof);
  r.CV9 = hex(await gcm(proof, N2, C));
  // INT-11.7 steps 3 and 4: non-extractable keys, the X25519 result never a JavaScript value.
  const cNx = await s.importKey('pkcs8', pkcs8('%(c)s'), X, false, ['deriveKey']);
  const iNx = await s.importKey('pkcs8', pkcs8('%(i)s'), X, false, ['deriveKey']);
  const chain = async (secret, info, usage) => s.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: empty, info },
    await s.deriveKey({ name: 'X25519', public: await raw(A) }, secret, 'HKDF', false, ['deriveKey']),
    { name: 'AES-GCM', length: 256 }, false, [usage]);
  const requestNx = await chain(cNx, cat(text('browser-bridge request key v1'), C, A), 'encrypt');
  const replyNx = await chain(cNx, cat(text('browser-bridge reply key v1'), C, A), 'decrypt');
  const proofNx = await chain(iNx, cat(text('browser-bridge proof key v1'), C, A, I), 'encrypt');
  if (requestNx.extractable || replyNx.extractable || proofNx.extractable) throw new Error('extractable key');
  r.CV4_by_derive_key = hex(await s.encrypt({ name: 'AES-GCM', iv: N1 }, requestNx, text('%(p1)s')));
  r.CV5_opened_by_derive_key = hex(await s.decrypt({ name: 'AES-GCM', iv: N1 }, replyNx, bytes(r.CV5)));
  r.CV9_by_derive_key = hex(await s.encrypt({ name: 'AES-GCM', iv: N2 }, proofNx, C));
  // RFC 5869 appendix A.1 to A.3 (OKM), NIST CAVP G1 to G3.
  const ikm22 = new Uint8Array(22).fill(0x0b);
  r.HKDF_A1 = hex(await hkdf(ikm22, seq(0x00, 0x0c), seq(0xf0, 0xf9), 42 * 8));
  r.HKDF_A2 = hex(await hkdf(seq(0x00, 0x4f), seq(0x60, 0xaf), seq(0xb0, 0xff), 82 * 8));
  r.HKDF_A3 = hex(await hkdf(ikm22, empty, empty, 42 * 8));
  r.GCM_G1 = hex(await gcm(bytes('b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4'),
    bytes('516c33929df5a3284ff463d7'), empty));
  r.GCM_G2 = hex(await gcm(bytes('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22'),
    bytes('0d18e06c7c725ac9e362e1ce'), bytes('2db5168e932556f8089a0622981d017d')));
  r.GCM_G3 = hex(await gcm(bytes('24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f'),
    bytes('9ff18563b978ec281b3f2794'),
    bytes('27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c'),
    bytes('adb5ec720ccf9898500028bf34afccbcaca126ef')));
  return r;
})()""" % {"c": C_SECRET, "a": A_SECRET, "i": I_SECRET, "p1": P1, "p2": P2}

RUN = {}


def setUpModule():
    RUN["start"] = time.time()


def tearDownModule():
    # LD-276: after the run, macOS's own log shows no keychain write by a PID of the run.
    found = driver.keychain_commits(driver.keychain_log(RUN["start"], time.time()), driver.RUN_PIDS | {os.getpid()})
    if found:
        raise driver.OwnerFilesChanged("STOP (LD-276): a process of this run wrote a keychain: " + "; ".join(found))


class ChannelVectorsInWebCrypto(unittest.TestCase):
    def test_t79_webcrypto_gives_int_01_50s_bytes(self):
        with driver.Chrome() as chrome:  # close() fails on a guard hit, a focus change or a changed owner file
            worker = chrome.worker(chrome.load_extension(DEMO))
            got = worker.eval(SCRIPT)
        self.assertEqual(set(got), set(EXPECTED))
        for name, value in EXPECTED.items():
            self.assertEqual(got[name], value, name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
