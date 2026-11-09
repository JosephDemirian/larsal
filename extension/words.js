// The pairing words of INT-11.39 (INT-02.5): the same four words Larsal shows in
// its Connect dialog. Pure: the caller gives the SHA-256 digest and the lines of
// words.txt; tested under macOS's jsc (INT-11.43, extension/test/pure_test.js).

/** The ASCII text the digest starts with; A, C and the identification key follow (32 bytes each). */
export const PAIRING = 'browser-bridge pairing v1';

/** The size of Larsal's word list (FEA-03): N is read in base 7,776. */
export const WORDS = 7_776;

/**
 * The four words: N is the first 8 bytes of `digest` as an unsigned big-endian
 * number; word i is line (N mod 7,776) of `list` (line 0 first), then N = N div 7,776.
 */
export function pairingWords(digest, list) {
  let n = 0n;
  for (const b of digest.slice(0, 8)) n = (n << 8n) | BigInt(b);
  const out = [];
  for (let i = 0; i < 4; i++) {
    out.push(list[Number(n % BigInt(WORDS))].toLowerCase());
    n /= BigInt(WORDS);
  }
  return out;
}
