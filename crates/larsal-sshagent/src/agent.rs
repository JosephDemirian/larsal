//! The OpenSSH agent protocol, client side (INT-06.11 to INT-06.20).

use crate::{Error, Failure};
use larsal_crypto::secret::SecretBytes;
use larsal_crypto::ssh::AgentKey;
use std::ffi::OsStr;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Longest agent reply Larsal reads, in bytes: the OpenSSH agent's own limit.
pub const MAX_REPLY: usize = 262_144;
/// Time for the connect plus the whole reply of one request.
pub const TIMEOUT: Duration = Duration::from_secs(2);
/// Longest socket path, in bytes (the macOS limit is 104 with the final zero).
pub const MAX_SOCKET_PATH: usize = 103;
/// Largest lifetime Larsal sends, in seconds (INT-06.20).
pub const MAX_LIFETIME: u32 = 999_999_999;
/// The security key provider when the caller names none (INT-06.38).
pub const SK_PROVIDER_DEFAULT: &str = "internal";

// Message numbers (draft-ietf-sshm-ssh-agent).
pub(crate) const FAILURE: u8 = 5;
pub(crate) const SUCCESS: u8 = 6;
pub(crate) const REQUEST_IDENTITIES: u8 = 11;
pub(crate) const IDENTITIES_ANSWER: u8 = 12;
pub(crate) const SIGN_REQUEST: u8 = 13;
pub(crate) const SIGN_RESPONSE: u8 = 14;
const ADD_IDENTITY: u8 = 17;
pub(crate) const REMOVE_IDENTITY: u8 = 18;
pub(crate) const REMOVE_ALL_IDENTITIES: u8 = 19;
pub(crate) const LOCK: u8 = 22;
pub(crate) const UNLOCK: u8 = 23;
const ADD_ID_CONSTRAINED: u8 = 25;
pub(crate) const EXTENSION: u8 = 27;
// Limit (constraint) bytes.
const CONSTRAIN_LIFETIME: u8 = 1;
const CONSTRAIN_CONFIRM: u8 = 2;
const CONSTRAIN_EXTENSION: u8 = 255;
const SK_PROVIDER_EXTENSION: &[u8] = b"sk-provider@openssh.com";

/// INT-06.12: Larsal sends at most one request at a time.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Device and inode of Larsal's own agent sockets while they run (R06-4).
static OWN_SOCKETS: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

/// Notes (`on`) or forgets Larsal's own agent socket `id`, so that a system
/// agent path leading to it counts as no system agent (R06-4).
pub(crate) fn own_socket(id: (u64, u64), on: bool) {
    let mut all = OWN_SOCKETS.lock().unwrap_or_else(PoisonError::into_inner);
    all.retain(|s| *s != id);
    if on {
        all.push(id);
    }
}

/// Limits sent with an add (INT-06.15).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    /// Seconds until the agent drops the key by itself: 1 to [`MAX_LIFETIME`].
    pub lifetime: Option<u32>,
    /// The agent asks before each use (the confirm limit).
    pub confirm: bool,
    /// The security key provider for `sk-` keys; `None` sends
    /// [`SK_PROVIDER_DEFAULT`]. Ignored for other keys.
    pub sk_provider: Option<String>,
}

/// One key the agent holds (INT-06.19). Public data only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The public key blob.
    pub blob: Vec<u8>,
    /// The comment, with invalid UTF-8 replaced.
    pub comment: String,
}

/// The agent behind one socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    path: PathBuf,
}

impl Agent {
    /// The agent to use now (INT-06.11): `socket_override` (S-SSH-02) when
    /// it is not empty after trimming spaces, else `SSH_AUTH_SOCK` from this
    /// process's environment, read at this call. Neither: [`Error::NoAgent`].
    pub fn locate(socket_override: &str) -> Result<Self, Error> {
        Self::choose(
            socket_override,
            std::env::var_os("SSH_AUTH_SOCK").as_deref(),
        )
    }

    /// [`Agent::locate`] with the environment value given by the caller.
    pub fn choose(socket_override: &str, auth_sock: Option<&OsStr>) -> Result<Self, Error> {
        let chosen = socket_override.trim_matches(' ');
        if !chosen.is_empty() {
            return Ok(Self::at(chosen));
        }
        match auth_sock {
            Some(sock) if !sock.is_empty() => Ok(Self::at(sock)),
            _ => Err(Error::NoAgent),
        }
    }

    /// The agent at `path`, used as given.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Adds `key` with `comment` and `limits` (INT-06.15, INT-06.16):
    /// message 17 when no limit applies, else 25 with, in this order, the
    /// lifetime, the confirm limit and, for `sk-` keys always, the provider
    /// extension. A lifetime of 0 or above [`MAX_LIFETIME`] is
    /// [`Error::Lifetime`] and nothing is sent. Reply 6 is success, 5 is
    /// [`Error::AddRefused`]. The message holding the private key lives only
    /// in a buffer wiped on drop.
    pub fn add(&self, key: &AgentKey, comment: &str, limits: &Limits) -> Result<(), Error> {
        let security_key = key.algorithm().starts_with("sk-");
        let mut tail = Vec::new();
        if let Some(seconds) = limits.lifetime {
            if !(1..=MAX_LIFETIME).contains(&seconds) {
                return Err(Error::Lifetime);
            }
            tail.push(CONSTRAIN_LIFETIME);
            tail.extend_from_slice(&seconds.to_be_bytes());
        }
        if limits.confirm {
            tail.push(CONSTRAIN_CONFIRM);
        }
        if security_key {
            let provider = limits.sk_provider.as_deref().unwrap_or(SK_PROVIDER_DEFAULT);
            tail.push(CONSTRAIN_EXTENSION);
            put_string(&mut tail, SK_PROVIDER_EXTENSION);
            put_string(&mut tail, provider.as_bytes());
        }
        let kind = if tail.is_empty() {
            ADD_IDENTITY
        } else {
            ADD_ID_CONSTRAINED
        };
        let refused = Error::AddRefused {
            lifetime: limits.lifetime.is_some(),
            security_key,
        };
        // An add the agent cannot take (its limit is MAX_REPLY) is not sent.
        let msg = add_message(kind, key.fields().expose(), comment.as_bytes(), &tail)
            .ok_or_else(|| refused.clone())?;
        match self.request(msg.expose())?.first() {
            Some(&SUCCESS) => Ok(()),
            Some(&FAILURE) => Err(refused),
            _ => Err(self.unreachable(Failure::Protocol)),
        }
    }

    /// Removes the key with this public blob (INT-06.17, message 18). `true`
    /// when the agent removed it (reply 6), `false` when it did not hold it
    /// (reply 5), which is not an error.
    pub fn remove(&self, public_blob: &[u8]) -> Result<bool, Error> {
        let mut body = vec![REMOVE_IDENTITY];
        put_string(&mut body, public_blob);
        match self
            .request(&frame(body).ok_or_else(|| self.unreachable(Failure::TooLong))?)?
            .first()
        {
            Some(&SUCCESS) => Ok(true),
            Some(&FAILURE) => Ok(false),
            _ => Err(self.unreachable(Failure::Protocol)),
        }
    }

    /// Removes every key the agent holds, also keys other programs added
    /// (INT-06.18): one message 19, nothing else. Reply 6 is success
    /// (MI06-20); reply 5 is [`Error::RemoveAllRefused`] (MI06-21).
    pub fn remove_all(&self) -> Result<(), Error> {
        match self.request(&[0, 0, 0, 1, REMOVE_ALL_IDENTITIES])?.first() {
            Some(&SUCCESS) => Ok(()),
            Some(&FAILURE) => Err(Error::RemoveAllRefused),
            _ => Err(self.unreachable(Failure::Protocol)),
        }
    }

    /// The keys the agent holds (INT-06.19, message 11, reply 12). A count
    /// that cannot fit the reply is refused before anything is allocated.
    pub fn list(&self) -> Result<Vec<Identity>, Error> {
        let reply = self.request(&[0, 0, 0, 1, REQUEST_IDENTITIES])?;
        parse_identities(&reply).ok_or_else(|| self.unreachable(Failure::Protocol))
    }

    /// One request on its own connection (INT-06.12 to INT-06.14): check
    /// the socket, connect, check the peer, write `msg`, read one reply
    /// within [`TIMEOUT`], close. Returns the reply body (number first).
    fn request(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let _one = ONE_AT_A_TIME.lock().unwrap_or_else(PoisonError::into_inner);
        let deadline = Instant::now()
            .checked_add(TIMEOUT)
            .ok_or_else(|| self.unreachable(Failure::Timeout))?;
        let mut stream = self.connect()?;
        let fail = |why| self.unreachable(why);
        write_full(&mut stream, msg, deadline).map_err(fail)?;
        let mut len = [0u8; 4];
        read_full(&mut stream, &mut len, deadline).map_err(fail)?;
        let len = usize::try_from(u32::from_be_bytes(len)).map_err(|_| fail(Failure::TooLong))?;
        if len > MAX_REPLY {
            return Err(fail(Failure::TooLong));
        }
        if len == 0 {
            return Err(fail(Failure::Protocol));
        }
        let mut body = vec![0; len];
        read_full(&mut stream, &mut body, deadline).map_err(fail)?;
        Ok(body)
    }

    /// INT-06.13: before connecting, the path is at most
    /// [`MAX_SOCKET_PATH`] bytes, is a socket (a final link is not
    /// followed) and belongs to this user; after, the peer runs as this
    /// user. Any failed check, a missing socket included (LD-183 (1)), is
    /// MI06-03 and nothing is sent; a refused connect is MI06-02. Larsal's
    /// own agent socket (same device and inode) is [`Error::NoAgent`]
    /// (R06-4): Larsal never talks to itself.
    ///
    /// The connect cannot hang: on macOS a Unix socket connect never waits
    /// for the listener (a full queue is refused at once); the reply wait
    /// is bounded by [`TIMEOUT`].
    pub(crate) fn connect(&self) -> Result<UnixStream, Error> {
        let own = larsal_platform::macos::effective_uid();
        let not_ours = || Error::NotOurSocket {
            path: self.path.clone(),
        };
        if self.path.as_os_str().len() > MAX_SOCKET_PATH {
            return Err(not_ours());
        }
        let meta = std::fs::symlink_metadata(&self.path).map_err(|_| not_ours())?;
        if !meta.file_type().is_socket() || meta.uid() != own {
            return Err(not_ours());
        }
        if OWN_SOCKETS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(meta.dev(), meta.ino()))
        {
            return Err(Error::NoAgent);
        }
        let stream =
            UnixStream::connect(&self.path).map_err(|_| self.unreachable(Failure::Connect))?;
        match larsal_platform::macos::peer_uid(&stream) {
            Ok(uid) if uid == own => Ok(stream),
            _ => Err(not_ours()),
        }
    }

    fn unreachable(&self, why: Failure) -> Error {
        Error::Unreachable {
            path: self.path.clone(),
            why,
        }
    }
}

/// The time left until `deadline`; none left is a timeout.
fn left(deadline: Instant) -> Result<Duration, Failure> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Failure::Timeout)
}

fn io_failure(e: &std::io::Error) -> Failure {
    match e.kind() {
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Failure::Timeout,
        _ => Failure::Closed,
    }
}

/// Fills `buf` from `stream`, all of it before `deadline`.
pub(crate) fn read_full(
    stream: &mut UnixStream,
    mut buf: &mut [u8],
    deadline: Instant,
) -> Result<(), Failure> {
    while !buf.is_empty() {
        stream
            .set_read_timeout(Some(left(deadline)?))
            .map_err(|_| Failure::Closed)?;
        match stream.read(buf) {
            Ok(0) => return Err(Failure::Closed),
            Ok(n) => {
                buf = std::mem::take(&mut buf)
                    .get_mut(n..)
                    .ok_or(Failure::Closed)?
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_failure(&e)),
        }
    }
    Ok(())
}

/// Writes all of `buf` to `stream` before `deadline`.
pub(crate) fn write_full(
    stream: &mut UnixStream,
    mut buf: &[u8],
    deadline: Instant,
) -> Result<(), Failure> {
    while !buf.is_empty() {
        stream
            .set_write_timeout(Some(left(deadline)?))
            .map_err(|_| Failure::Closed)?;
        match stream.write(buf) {
            Ok(0) => return Err(Failure::Closed),
            Ok(n) => buf = buf.get(n..).ok_or(Failure::Closed)?,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io_failure(&e)),
        }
    }
    Ok(())
}

/// Appends an SSH `string`: `uint32` length, then the bytes. Callers keep
/// lengths far below 4 GiB (agent messages are at most [`MAX_REPLY`]).
pub(crate) fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// `uint32` length and `body`; `None` over [`MAX_REPLY`].
pub(crate) fn frame(body: Vec<u8>) -> Option<Vec<u8>> {
    if body.len() > MAX_REPLY {
        return None;
    }
    let mut out = u32::try_from(body.len()).ok()?.to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    Some(out)
}

/// The framed add message, built in place in a wiped buffer of its exact
/// size: length, `kind`, the key's type and private fields, `string`
/// comment, the limits. `None` when it would pass the agent's limit.
fn add_message(kind: u8, fields: &[u8], comment: &[u8], tail: &[u8]) -> Option<SecretBytes> {
    let comment_len = u32::try_from(comment.len()).ok()?.to_be_bytes();
    let parts: [&[u8]; 5] = [&[kind], fields, &comment_len, comment, tail];
    let body_len = parts
        .iter()
        .try_fold(0usize, |sum, p| sum.checked_add(p.len()))?;
    if body_len > MAX_REPLY {
        return None;
    }
    let mut msg = SecretBytes::zeroed(body_len.checked_add(4)?);
    let mut rest = msg.expose_mut();
    put(&mut rest, &u32::try_from(body_len).ok()?.to_be_bytes())?;
    for part in parts {
        put(&mut rest, part)?;
    }
    rest.is_empty().then_some(msg)
}

/// Copies `bytes` to the front of `rest` and moves `rest` past them.
fn put(rest: &mut &mut [u8], bytes: &[u8]) -> Option<()> {
    let (head, tail) = std::mem::take(rest).split_at_mut_checked(bytes.len())?;
    head.copy_from_slice(bytes);
    *rest = tail;
    Some(())
}

pub(crate) fn take_u32(rest: &mut &[u8]) -> Option<u32> {
    let (head, tail) = rest.split_first_chunk::<4>()?;
    *rest = tail;
    Some(u32::from_be_bytes(*head))
}

pub(crate) fn take_string<'a>(rest: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::try_from(take_u32(rest)?).ok()?;
    let (head, tail) = rest.split_at_checked(len)?;
    *rest = tail;
    Some(head)
}

/// Reply 12: `uint32` count, then `string` blob and `string` comment per key.
pub(crate) fn parse_identities(reply: &[u8]) -> Option<Vec<Identity>> {
    let (&kind, mut rest) = reply.split_first()?;
    if kind != IDENTITIES_ANSWER {
        return None;
    }
    let count = usize::try_from(take_u32(&mut rest)?).ok()?;
    // Each key takes at least two 4-byte lengths.
    if count > rest.len().checked_div(8)? {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let blob = take_string(&mut rest)?.to_vec();
        let comment = String::from_utf8_lossy(take_string(&mut rest)?).into_owned();
        out.push(Identity { blob, comment });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_parse_and_bounds() {
        let mut ok = vec![IDENTITIES_ANSWER, 0, 0, 0, 1];
        put_string(&mut ok, b"blob");
        put_string(&mut ok, b"c\xffx");
        let ids = parse_identities(&ok).unwrap();
        assert_eq!(ids[0].blob, b"blob");
        assert_eq!(ids[0].comment, "c\u{fffd}x");
        // T36: a count of 1,000,000 in a 9-byte reply.
        assert!(parse_identities(&[12, 0, 0x0f, 0x42, 0x40, 0, 0, 0, 0]).is_none());
        // Truncated entries and wrong numbers.
        assert!(parse_identities(&ok[..ok.len() - 1]).is_none());
        assert!(parse_identities(&[5]).is_none());
        assert!(parse_identities(&[]).is_none());
        assert_eq!(parse_identities(&[12, 0, 0, 0, 0]), Some(vec![]));
    }

    proptest::proptest! {
        /// Hostile replies (INT-06.19): any bytes give a list or `None`, never a panic.
        #[test]
        fn hostile_identities_never_panic(mut reply in proptest::collection::vec(0u8..=255, 0..600)) {
            if let Some(first) = reply.first_mut() {
                *first = IDENTITIES_ANSWER;
            }
            let _ = parse_identities(&reply);
        }
    }

    #[test]
    fn add_message_is_exact_and_bounded() {
        let msg = add_message(25, b"FIELDS", b"c", &[1, 0, 0, 0, 120]).unwrap();
        assert_eq!(
            msg.expose(),
            b"\0\0\0\x11\x19FIELDS\0\0\0\x01c\x01\0\0\0\x78".as_slice()
        );
        assert!(add_message(17, &vec![0; MAX_REPLY], b"", &[]).is_none());
    }

    #[test]
    fn override_wins_then_environment() {
        let env = Some(OsStr::new("/tmp/env.sock"));
        assert_eq!(
            Agent::choose("  /tmp/o.sock ", env).unwrap().path(),
            Path::new("/tmp/o.sock")
        );
        assert_eq!(
            Agent::choose("   ", env).unwrap().path(),
            Path::new("/tmp/env.sock")
        );
        assert_eq!(Agent::choose("", Some(OsStr::new(""))), Err(Error::NoAgent));
    }
}
