// The wire of INT-01: strict base64 (INT-01.26) and the request table of one
// session (INT-11.10). Pure: no browser API, tested under macOS's jsc
// (INT-11.43, extension/test/pure_test.js).

const ABC = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Requests in flight per session (INT-01.44); more wait in order. */
export const MAX_IN_FLIGHT = 8;

/** Base64 with the standard alphabet and `=` padding (RFC 4648 section 4). */
export function encode(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += ABC[n >> 18] + ABC[(n >> 12) & 63];
    out += i + 1 < bytes.length ? ABC[(n >> 6) & 63] : '=';
    out += i + 2 < bytes.length ? ABC[n & 63] : '=';
  }
  return out;
}

/**
 * Decodes `text` strictly (INT-01.26): the standard alphabet only, exact
 * padding, zero trailing bits. Returns the bytes when there are exactly
 * `size` of them (at least `size` with `atLeast`), else null.
 */
export function decode(text, size, atLeast = false) {
  if (typeof text !== 'string' || text.length % 4 !== 0) return null;
  const pad = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  const length = (text.length / 4) * 3 - pad;
  if (atLeast ? length < size : length !== size) return null;
  const out = new Uint8Array(length);
  let bits = 0;
  let acc = 0;
  let j = 0;
  for (let i = 0; i < text.length - pad; i++) {
    const v = ABC.indexOf(text[i]);
    if (v < 0) return null;
    acc = ((acc << 6) | v) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (acc >> bits) & 255;
    }
  }
  return acc & ((1 << bits) - 1) ? null : out;
}

/** Whether two byte arrays hold the same bytes. */
export function same(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

/**
 * One session's requests (INT-11.10): each gets the next `req` (1, 2, ...);
 * at most `max` are in flight, later ones wait in order. A job is any object;
 * the caller sets `job.nonce` before it sends the request.
 */
export class Requests {
  constructor(max = MAX_IN_FLIGHT) {
    this.max = max;
    this.next = 1;
    this.flying = new Map();
    this.queue = [];
  }

  /** Takes `job`: its `req` when it may go now, else 0 (it waits in the queue). */
  add(job) {
    if (this.flying.size >= this.max) {
      this.queue.push(job);
      return 0;
    }
    return this.fly(job);
  }

  fly(job) {
    const req = this.next++;
    this.flying.set(req, job);
    return req;
  }

  /** Ends request `req`; returns [req, job] of the queued job that may go now, or null. */
  done(req) {
    this.flying.delete(req);
    const job = this.flying.size < this.max ? this.queue.shift() : undefined;
    return job ? [this.fly(job), job] : null;
  }

  /** The session ended: every job, in flight then queued, leaves the table. */
  drain() {
    const all = [...this.flying.values(), ...this.queue];
    this.flying.clear();
    this.queue = [];
    return all;
  }

  /**
   * What an opened box is (INT-11.10, INT-01.46): the `req` of the waiting
   * request it answers (same `req`, same `type`, and the nonce of that
   * request), "notice" for a box without `req` that says it is a notice, or
   * null: anything else is dropped without effect.
   */
  match(content, nonce) {
    if (!content || typeof content !== 'object' || Array.isArray(content)) return null;
    if (!Object.hasOwn(content, 'req')) return content.type === 'notice' ? 'notice' : null;
    const job = this.flying.get(content.req);
    return job && job.nonce && same(job.nonce, nonce) && job.type === content.type ? content.req : null;
  }
}
