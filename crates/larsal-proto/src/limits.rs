//! Every size and time of the wire protocol (SYN-01.8, SYN-01.10,
//! SYN-01.11; architecture "Rules for this part" 4). Each is checked before
//! anything is allocated for the part it bounds. The server takes them as
//! its defaults, and a test may lower any of them.

use std::time::Duration;

/// The request line, in bytes: over this it gets 414 (SYN-01.10).
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// One header field (`name: value`), in bytes: over this it gets 431.
pub const MAX_HEADER_FIELD: usize = 8 * 1024;
/// The whole request head, request line included, in bytes: over this it
/// gets 431 (hyper's `max_header_size`, also for a head not yet complete).
pub const MAX_HEAD: usize = 32 * 1024;
/// Header fields in one request: more gets 431 (hyper's `max_headers`).
pub const MAX_HEADERS: usize = 100;
/// A JSON body or reply, in bytes (nginx's `client_max_body_size 1m`).
pub const MAX_JSON: usize = 1024 * 1024;
/// A wrap record (CRY-04.6), in bytes.
pub const MAX_WRAP: usize = 4 * 1024;
/// A vault body, in bytes: FMT-01.31's vault file limit, 1 GiB + 64 MiB
/// (LD-263 (13), LD-267 (7)). The largest body any route takes.
pub const MAX_VAULT: u64 = 1_140_850_688;
/// Levels of arrays and objects in a record; the top object is level 1
/// (SYN-01.8, LD-273 (1)).
pub const MAX_RECORD_DEPTH: usize = 8;
/// The largest version, size or time in a record: 2^53 − 1 (SYN-01.8).
pub const MAX_RECORD_NUMBER: u64 = (1 << 53) - 1;

/// A device name, in Unicode scalar values (SYN-04.2, LD-273 (1)).
pub const MAX_DEVICE_NAME: usize = 64;
/// A sign-in signature: strict DER of P-256, at most 72 bytes (CRY-04.4).
pub const MAX_SIGNATURE: usize = 72;

/// A sign-in challenge is valid this long (SYN-04.3; WebAuthn Level 3's
/// default ceremony timeout).
pub const CHALLENGE_SECONDS: u64 = 300;
/// A session ends this long after its last use (SYN-04.5; OWASP).
pub const SESSION_IDLE_SECONDS: u64 = 15 * 60;
/// A session ends this long after it was made, used or not (SYN-04.5).
pub const SESSION_MAX_SECONDS: u64 = 8 * 60 * 60;

/// Requests per IP address and minute to the sign-in routes (SYN-01.12).
pub const SIGNIN_PER_MINUTE: u32 = 10;
/// POST, PUT and DELETE requests per IP address and minute on every other
/// route (SYN-01.12).
pub const WRITES_PER_MINUTE: u32 = 60;
/// GET requests per IP address and minute on every other route
/// (SYN-01.12).
pub const READS_PER_MINUTE: u32 = 200;

/// The TLS handshake, from the accepted connection (SYN-01.11; Larsal's own
/// value, equal to the head's, LD-273 (1)).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// The request head, from the end of the handshake or of the last reply
/// (hyper's `header_read_timeout`, which also closes an idle connection).
pub const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest gap between two reads of a body or two writes of a reply
/// (nginx's `client_body_timeout` and `send_timeout`).
pub const GAP_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn01_10_vault_limit_is_fmt01_31() {
        let fmt = larsal_format::limits::Limits::DEFAULT.total_file;
        assert_eq!(MAX_VAULT, u64::try_from(fmt).unwrap());
    }

    #[test]
    fn syn01_10_limits_are_the_cards_values() {
        assert_eq!(
            (MAX_REQUEST_LINE, MAX_HEADER_FIELD, MAX_HEAD, MAX_HEADERS),
            (8192, 8192, 32768, 100)
        );
        assert_eq!((MAX_JSON, MAX_WRAP), (1_048_576, 4096));
        assert_eq!(
            (MAX_RECORD_DEPTH, MAX_RECORD_NUMBER),
            (8, 9_007_199_254_740_991)
        );
        let secs = [HANDSHAKE_TIMEOUT, HEAD_TIMEOUT, GAP_TIMEOUT].map(|d| d.as_secs());
        assert_eq!(secs, [30, 30, 60]);
    }

    #[test]
    fn syn04_and_syn01_12_values_are_the_cards() {
        assert_eq!((MAX_DEVICE_NAME, MAX_SIGNATURE), (64, 72));
        assert_eq!(
            (CHALLENGE_SECONDS, SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS),
            (300, 900, 28_800)
        );
        assert_eq!(
            (SIGNIN_PER_MINUTE, WRITES_PER_MINUTE, READS_PER_MINUTE),
            (10, 60, 200)
        );
    }
}
