// The channel of INT-01.49 in the browser's own WebCrypto (INT-11.7, LD-274 (1)):
// X25519, HKDF-SHA256 with an empty salt and one key per direction, and
// AES-256-GCM with 12-byte nonces, a 128-bit tag and no associated data. The
// extension ships no crypto code of its own.
//
// Guarantees: every key made here is non-extractable but the public halves;
// the X25519 results never become JavaScript values (deriveKey straight from
// X25519 into HKDF); the request and proof keys can only encrypt, the reply
// key can only decrypt. An all-zero X25519 result rejects with OperationError
// (W3C WebCrypto, X25519 "Derive Bits").

const subtle = crypto.subtle;
const X25519 = { name: 'X25519' };
const LABELS = {
  request: 'browser-bridge request key v1',
  reply: 'browser-bridge reply key v1',
  proof: 'browser-bridge proof key v1',
};

const ascii = (text) => Uint8Array.from(text, (c) => c.charCodeAt(0));

function join(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** A fresh X25519 key pair whose private key cannot be exported (INT-11.6, INT-11.7). */
export function keyPair() {
  return subtle.generateKey(X25519, false, ['deriveKey']);
}

/** The raw 32 bytes of an X25519 public key. */
export async function publicBytes(key) {
  return new Uint8Array(await subtle.exportKey('raw', key));
}

/** The HKDF key of X25519(`secret`, `their`): the result itself is never a JavaScript value. */
async function agree(secret, their) {
  const pub = await subtle.importKey('raw', their, X25519, true, []);
  return subtle.deriveKey({ name: 'X25519', public: pub }, secret, 'HKDF', false, ['deriveKey']);
}

function expand(hkdf, info, usage) {
  const params = { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info };
  return subtle.deriveKey(params, hkdf, { name: 'AES-GCM', length: 256 }, false, [usage]);
}

/**
 * The session's two keys (INT-01.49) from the client's secret `c`, its public
 * key `C` and Larsal's public key `A` (32 bytes each): `request` (encrypt
 * only) and `reply` (decrypt only).
 */
export async function sessionKeys(c, C, A) {
  const hkdf = await agree(c, A);
  return {
    request: await expand(hkdf, join(ascii(LABELS.request), C, A), 'encrypt'),
    reply: await expand(hkdf, join(ascii(LABELS.reply), C, A), 'decrypt'),
  };
}

/** The proof key (INT-01.49, INT-01.28) from the identification secret `i` and its public key `I`. */
export async function proofKey(i, C, A, I) {
  return expand(await agree(i, A), join(ascii(LABELS.proof), C, A, I), 'encrypt');
}

/** The box of INT-01.21: ciphertext then the 16-byte tag. */
export async function seal(key, nonce, bytes) {
  return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, bytes));
}

/** Opens a box; rejects when it does not open. */
export async function open(key, nonce, box) {
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, box));
}
