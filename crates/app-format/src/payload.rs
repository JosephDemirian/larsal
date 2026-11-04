//! Opening a payload (FMT-05.7, FMT-05.13, FMT-06 to FMT-09, FMT-17): the one
//! open order, decryption with the streaming decryptor (LD-69), and gzip
//! with limits.
//!
//! Guarantees: steps run in the order of FMT-05.7 and stop at the first
//! fault; no KDF work before the header hash and the cost check pass; no
//! payload byte is decrypted before the header HMAC and every block HMAC
//! pass; no byte is decompressed or parsed before the padding check; every
//! decrypted or decompressed byte lives in [`SecretBytes`]; nothing is
//! allocated from a declared size (gzip ISIZE included). Version 3 follows
//! FMT-05.13: no KDF work before the ciphertext length and cost checks; no
//! byte is decompressed before the start bytes and every hashed block pass;
//! the padding is never checked (LD-01).

use crate::buffer::Grow;
use crate::detect;
use crate::error::Error;
use crate::hashed_blocks::read_hashed_blocks;
use crate::header::{Compression, Header, read_header};
use crate::inner::{InnerHeader, PoolItem, StreamAlgorithm, read_inner};
use crate::integrity::{header_hash_ok, header_hmac_ok, read_blocks};
use crate::keys::{
    Credentials, LockedKey, TransformedKey, cipher_key_v3, composite_key, final_keys,
    hardware_part, password_part,
};
use crate::limits::{Limit, Limits};
use app_crypto::cipher::{Cipher, Decryptor, Encryptor};
use app_crypto::kdf::{self, CostReport, Host, KdfParams, Verdict};
use app_crypto::secret::{SecretBytes, ct_eq};
use app_crypto::stream::FieldStream;
use flate2::{Compress, Crc, Decompress, FlushCompress, FlushDecompress, Status};

/// The result of [`open_payload`] that is not an error.
pub enum Open {
    /// The KDF cost is in the ask band of CRY-02.14: show the report, and on
    /// yes call [`open_payload`] again with it as the approval. Not an
    /// error; no key work has run (FMT-04.21 step 2).
    Ask(CostReport),
    /// The key is proven and every layer passed.
    Opened(Box<Payload>),
}

impl core::fmt::Debug for Open {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ask(report) => f.debug_tuple("Ask").field(report).finish(),
            Self::Opened(_) => f.write_str("Opened([hidden])"),
        }
    }
}

/// The opened parts of a vault, ready for the document reader.
pub struct Payload {
    /// The outer header, authenticated by the header HMAC (version 4).
    pub header: Header,
    /// The inner header: stream algorithm and key, and the attachment pool
    /// (each item a range of the payload, see [`Xml::pool_item`]).
    pub inner: InnerHeader,
    /// The protected-field keystream, positioned at byte 0 (FMT-09.11).
    pub field_stream: FieldStream,
    /// The XML document.
    pub xml: Xml,
    /// The transformed key of this open, for the next save's check (CRY-03.16).
    pub transformed_key: TransformedKey,
}

/// The XML document of a payload: everything after the inner header
/// (FMT-08.1; version 3: the whole document stream, FMT-17.16). It stays a
/// range of the decompressed buffer, so the document is never copied.
pub struct Xml {
    data: SecretBytes,
    range: core::ops::Range<usize>,
}

impl Xml {
    /// The document bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.data.expose().get(self.range.clone()).unwrap_or(&[])
    }

    /// The content of a version 4 pool item: it lies in the same
    /// decompressed buffer, before the document, and is not copied (LD-90).
    #[must_use]
    pub fn pool_item(&self, item: &PoolItem) -> &[u8] {
        self.data.expose().get(item.range.clone()).unwrap_or(&[])
    }
}

/// Opens a vault file down to its XML bytes. Version 4 runs the order of
/// FMT-05.7:
/// - read step: over `limits.total_file` with valid first 12 bytes, `TooLarge`;
/// - 0: no credential part at all, `NoCredentials`;
/// - 1: detection, version and header fields (FMT-01, FMT-02, FMT-03);
/// - 2, 3: under 64 bytes after the header, or a header SHA-256 mismatch, `Corrupt`;
/// - 4: the KDF cost check (`TooLarge`, or [`Open::Ask`]), then the hardware
///   key (`HardwareKey`), then the KDF;
/// - 5: header HMAC mismatch, `WrongKey` (the only `WrongKey`);
/// - 6: block stream, decryption and padding, gzip, inner header, document
///   size: `Corrupt` or `TooLarge`, never `WrongKey`.
///
/// `host` is this Mac's memory, processors and speed records (CRY-02.14);
/// a calibration run may fill in a missing record, for the caller to save.
/// `approval` is the report of an earlier [`Open::Ask`] the user approved.
/// Version 3 files (majors 2 and 3) follow FMT-05.13 instead: no hash or
/// HMAC after the header; the start bytes are the only `WrongKey`; hashed
/// blocks; no inner header ([`Payload::inner`] then holds field 8 and
/// Salsa20, with an empty pool). Their header hash is checked by the
/// document reader over `file[..header.len]` (FMT-05.12).
///
/// # Errors
/// One kind of FMT-01.33, from the first failing step above.
pub fn open_payload(
    file: &[u8],
    credentials: &Credentials<'_>,
    host: &mut Host,
    limits: &Limits,
    approval: Option<&CostReport>,
) -> Result<Open, Error> {
    detect::check_total(file, limits)?;
    if credentials.is_empty() {
        return Err(Error::NoCredentials);
    }
    let password = credentials
        .password
        .map(|p| LockedKey::new(password_part(p)));
    let header = read_header(file, limits)?;
    let (raw, after) = file.split_at_checked(header.len).ok_or(Error::Corrupt)?;
    if header.v3.is_some() {
        return open_v3(header, after, credentials, password, host, limits, approval);
    }
    let (hash, after) = after.split_first_chunk::<32>().ok_or(Error::Corrupt)?;
    let (hmac, stream) = after.split_first_chunk::<32>().ok_or(Error::Corrupt)?;
    if !header_hash_ok(raw, hash) {
        return Err(Error::Corrupt);
    }
    let seed = kdf_seed(&header.kdf).to_vec();
    let (transformed, _) = match key_work(
        &header.kdf,
        credentials,
        password,
        &seed,
        true,
        host,
        limits,
        approval,
    )? {
        Ok(keys) => keys,
        Err(report) => return Ok(Open::Ask(report)),
    };
    let keys = final_keys(&header.master_seed, &transformed);
    if !header_hmac_ok(&keys.hmac_key, raw, hmac) {
        return Err(Error::WrongKey);
    }
    let blocks = read_blocks(stream, &keys.hmac_key, limits)?;
    let (plain, plain_len) = decrypt(header.cipher, &keys.cipher_key, &header.iv, &blocks)?;
    drop(keys);
    // The decrypted plaintext is dropped (wiped) as soon as it is unzipped.
    let (data, u_len) = match header.compression {
        Compression::Gzip => {
            let u = gunzip(
                plain.expose().get(..plain_len).ok_or(Error::Corrupt)?,
                limits.total,
            )?;
            drop(plain);
            let n = u.len();
            (u, n)
        }
        Compression::None if plain_len > limits.total => return Err(Error::TooLarge(Limit::Total)),
        Compression::None => (plain, plain_len),
    };
    let u = data.expose().get(..u_len).ok_or(Error::Corrupt)?;
    let inner = read_inner(u, limits)?;
    if u_len.saturating_sub(inner.len) > limits.document {
        return Err(Error::TooLarge(Limit::Document));
    }
    let field_stream = inner.field_stream()?;
    let range = inner.len..u_len;
    let transformed_key = TransformedKey {
        key: transformed,
        kdf: header.kdf.clone(),
        v4: true,
    };
    Ok(Open::Opened(Box::new(Payload {
        header,
        inner,
        field_stream,
        xml: Xml { data, range },
        transformed_key,
    })))
}

/// The version 3 open after the header (FMT-05.13 steps 2 to 7, FMT-17):
/// ciphertext length, key work, start bytes (the only version 3
/// `WrongKey`), hashed blocks, gzip. The header hash inside the document
/// (step 8) is the document reader's, over `file[..header.len]`.
fn open_v3(
    header: Header,
    ciphertext: &[u8],
    credentials: &Credentials<'_>,
    password: Option<LockedKey>,
    host: &mut Host,
    limits: &Limits,
    approval: Option<&CostReport>,
) -> Result<Open, Error> {
    let v3 = header.v3.as_ref().ok_or(Error::Corrupt)?;
    if ciphertext.len() < 32 {
        return Err(Error::Corrupt); // step 2, before the KDF (D-05-4)
    }
    let seed = header.master_seed;
    let (transformed, hardware) = match key_work(
        &header.kdf,
        credentials,
        password,
        &seed,
        false,
        host,
        limits,
        approval,
    )? {
        Ok(keys) => keys,
        Err(report) => return Ok(Open::Ask(report)),
    };
    let key = LockedKey::new(cipher_key_v3(
        &header.master_seed,
        hardware.as_deref(),
        &transformed,
    ));
    drop(hardware); // R3 is not needed once the cipher key exists (SR-07)
    // Whole cipher blocks only: leftover bytes lie after the logical end (FMT-17.12).
    let whole = match header.cipher {
        Cipher::ChaCha20 => ciphertext.len(),
        _ => ciphertext.len().saturating_sub(ciphertext.len() % 16),
    };
    let ciphertext = ciphertext.get(..whole).ok_or(Error::Corrupt)?;
    let (plain, plain_len) =
        decrypt_v3(header.cipher, &key, &header.iv, ciphertext, &v3.start_bytes)?;
    drop(key);
    let stream = plain.expose().get(32..plain_len).ok_or(Error::Corrupt)?;
    let blocks = read_hashed_blocks(stream, limits)?;
    let joined = join(&blocks)?;
    drop(plain);
    let xml = match header.compression {
        Compression::Gzip => gunzip(joined.expose(), limits.total)?,
        Compression::None if joined.len() > limits.total => {
            return Err(Error::TooLarge(Limit::Total));
        }
        Compression::None => joined,
    };
    if xml.len() > limits.document {
        return Err(Error::TooLarge(Limit::Document));
    }
    let inner = InnerHeader {
        stream: StreamAlgorithm::Salsa20,
        stream_key: LockedKey::new(SecretBytes::new(v3.stream_key.clone())),
        pool: Vec::new(),
        len: 0,
    };
    let field_stream = inner.field_stream()?;
    let range = 0..xml.len();
    let transformed_key = TransformedKey {
        key: transformed,
        kdf: header.kdf.clone(),
        v4: false,
    };
    Ok(Open::Opened(Box::new(Payload {
        header,
        inner,
        field_stream,
        xml: Xml { data: xml, range },
        transformed_key,
    })))
}

/// The transformed key `T` that `credentials` give under `params`, the KDF
/// settings and seed of a file (FMT-04.11), the way an open of that file
/// derives it: with `v4` the hardware key is asked with the KDF seed and
/// its part goes into the composite key (FMT-04.6); without, as in
/// version 3, `T` holds no hardware part and no device is asked
/// (FMT-04.15). For the retired-key check (MOD-11.31): the settings are
/// ones this Mac already ran, so the ask band of CRY-02.14 does not ask
/// again (as a reload does); its refusals still hold.
///
/// # Errors
/// `NoCredentials` with no part at all; `HardwareKey` from the device;
/// `TooLarge(KdfCost)` or `Unsupported` for settings the KDF refuses.
pub fn transform(
    credentials: &Credentials<'_>,
    params: &KdfParams,
    v4: bool,
    host: &mut Host,
    limits: &Limits,
) -> Result<TransformedKey, Error> {
    if credentials.is_empty() {
        return Err(Error::NoCredentials);
    }
    let credentials = Credentials {
        hardware_key: credentials.hardware_key.filter(|_| v4),
        ..*credentials
    };
    let mut run = |approval: Option<&CostReport>| {
        let password = credentials
            .password
            .map(|p| LockedKey::new(password_part(p)));
        key_work(
            params,
            &credentials,
            password,
            kdf_seed(params),
            v4,
            host,
            limits,
            approval,
        )
    };
    let (key, _) = match run(None)? {
        Ok(keys) => keys,
        Err(report) => run(Some(&report))?.map_err(|_| Error::Unsupported)?,
    };
    Ok(TransformedKey {
        key,
        kdf: params.clone(),
        v4,
    })
}

/// The key work of FMT-05.7 step 4 (version 3: FMT-05.13 step 3): the cost
/// check, then the hardware key asked with `challenge`, then the KDF.
/// Version 4 hashes the hardware part into the composite key; version 3
/// returns it for the final key (FMT-04.15). The inner `Err` is the ask.
#[allow(clippy::too_many_arguments)]
fn key_work(
    params: &KdfParams,
    credentials: &Credentials<'_>,
    password: Option<LockedKey>,
    challenge: &[u8],
    v4: bool,
    host: &mut Host,
    limits: &Limits,
    approval: Option<&CostReport>,
) -> Result<Result<(LockedKey, Option<LockedKey>), CostReport>, Error> {
    let cleared = match kdf::assess(params, host, &limits.kdf, approval) {
        Ok(Verdict::Run(cleared)) => cleared,
        Ok(Verdict::Ask(report)) => return Ok(Err(report)),
        Err(app_crypto::Error::KdfCost) => return Err(Error::TooLarge(Limit::KdfCost)),
        Err(_) => return Err(Error::Unsupported),
    };
    let hardware = match credentials.hardware_key {
        Some(key) => Some(LockedKey::new(hardware_part(key, challenge)?)),
        None => None,
    };
    let composite = LockedKey::new(composite_key(
        password.as_deref(),
        credentials.key_file.map(|k| k.key()),
        if v4 { hardware.as_deref() } else { None },
    ));
    // Key parts the derivation does not need are gone before it runs, which
    // can take seconds (SR-07). Version 3 keeps R for the cipher key.
    drop(password);
    let hardware = hardware.filter(|_| !v4); // drops the v4 part here
    probe::count(|c| c.kdf = c.kdf.saturating_add(1));
    let transformed =
        LockedKey::new(kdf::derive(&composite, &cleared).map_err(|_| Error::Unsupported)?);
    Ok(Ok((transformed, hardware)))
}

/// The block data joined into one secret buffer of its exact size.
fn join(blocks: &[&[u8]]) -> Result<SecretBytes, Error> {
    let total = blocks
        .iter()
        .map(|b| b.len())
        .fold(0usize, usize::saturating_add);
    let mut out = SecretBytes::zeroed(total);
    let mut at: usize = 0;
    for b in blocks {
        let end = at.checked_add(b.len()).ok_or(Error::Corrupt)?;
        out.expose_mut()
            .get_mut(at..end)
            .ok_or(Error::Corrupt)?
            .copy_from_slice(b);
        at = end;
    }
    Ok(out)
}

/// The hardware key challenge of version 4: the KDF salt or seed (FMT-04.8).
fn kdf_seed(params: &KdfParams) -> &[u8] {
    match params {
        KdfParams::AesKdf { seed, .. } => seed,
        KdfParams::Argon2 { salt, .. } => salt,
    }
}

/// Bytes fed to the decryptor per call, so each returned piece is small.
const PIECE: usize = 64 * 1024;

/// Decrypts the joined `chunks` (version 4) into one buffer of their total
/// length and returns it with the plaintext length, the CBC padding checked
/// and stripped (FMT-08.5).
fn decrypt(
    cipher: Cipher,
    key: &SecretBytes,
    iv: &[u8],
    chunks: &[&[u8]],
) -> Result<(SecretBytes, usize), Error> {
    probe::count(|c| c.decrypt = c.decrypt.saturating_add(1));
    let total = chunks
        .iter()
        .map(|c| c.len())
        .fold(0usize, usize::saturating_add);
    let mut out = Out::new(total);
    let mut dec = Decryptor::new(cipher, key, iv).map_err(|_| Error::Corrupt)?;
    for piece in chunks.iter().flat_map(|c| c.chunks(PIECE)) {
        out.put(dec.update(piece).map_err(|_| Error::Corrupt)?)?;
    }
    out.put(dec.finish().map_err(|_| Error::Corrupt)?)?;
    if out.len == 0 {
        return Err(Error::Corrupt); // no inner header at all (FMT-08.14)
    }
    Ok((out.buf, out.len))
}

/// Version 3 (FMT-05.13 steps 4 and 5): decrypts only the first cipher
/// blocks, compares the 32 start bytes in constant time (`WrongKey` on a
/// mismatch, LD-12), and only then decrypts the rest: whole blocks, no
/// padding check (FMT-07.11, LD-41).
fn decrypt_v3(
    cipher: Cipher,
    key: &SecretBytes,
    iv: &[u8],
    ciphertext: &[u8],
    start_bytes: &[u8; 32],
) -> Result<(SecretBytes, usize), Error> {
    probe::count(|c| c.decrypt = c.decrypt.saturating_add(1));
    let mut out = Out::new(ciphertext.len());
    let mut dec = Decryptor::new(cipher, key, iv).map_err(|_| Error::Corrupt)?;
    // 48 bytes give the first 32 plaintext bytes (CBC holds back one block).
    let (head, rest) = ciphertext.split_at(ciphertext.len().min(48));
    out.put(dec.update(head).map_err(|_| Error::Corrupt)?)?;
    let mut dec = Some(dec);
    if rest.is_empty()
        && let Some(d) = dec.take()
    {
        out.put(d.finish_unpadded().map_err(|_| Error::Corrupt)?)?;
    }
    let start = out.buf.expose().get(..32).ok_or(Error::Corrupt)?;
    if out.len < 32 || !ct_eq(start, start_bytes) {
        return Err(Error::WrongKey); // FMT-05.11, LD-12
    }
    if let Some(mut d) = dec {
        for piece in rest.chunks(PIECE) {
            out.put(d.update(piece).map_err(|_| Error::Corrupt)?)?;
        }
        out.put(d.finish_unpadded().map_err(|_| Error::Corrupt)?)?;
    }
    Ok((out.buf, out.len))
}

/// A decryption output buffer of fixed size, filled in order.
struct Out {
    buf: SecretBytes,
    len: usize,
}

impl Out {
    fn new(n: usize) -> Self {
        Self {
            buf: SecretBytes::zeroed(n),
            len: 0,
        }
    }

    fn put(&mut self, piece: SecretBytes) -> Result<(), Error> {
        let end = self.len.checked_add(piece.len()).ok_or(Error::Corrupt)?;
        self.buf
            .expose_mut()
            .get_mut(self.len..end)
            .ok_or(Error::Corrupt)?
            .copy_from_slice(piece.expose());
        probe::count(|c| c.decrypted = c.decrypted.saturating_add(piece.len()));
        self.len = end;
        Ok(())
    }
}

/// Gunzips exactly one gzip member (FMT-08.6, FMT-08.7) into a buffer of
/// its exact size, never more than `limit` bytes. The first pass checks the
/// whole member (header, deflate data, CRC32, ISIZE, no trailing bytes) and
/// counts the output in a fixed buffer, so a bomb is stopped before any
/// output buffer exists (AT-A06); the second pass fills the result. Also for
/// compressed document items (FMT-13.5), with the attachment limit.
///
/// Limit: the inflate window inside flate2 holds up to 32 KiB of output and
/// is freed without a wipe; the crate offers no way to wipe it.
///
/// # Errors
/// `Corrupt` for any gzip fault; `TooLarge(Total)` past `limit` (a caller
/// with an attachment limit names its own).
pub fn gunzip(data: &[u8], limit: usize) -> Result<SecretBytes, Error> {
    probe::count(|c| c.inflate = c.inflate.saturating_add(1));
    let n = inflate(data, limit, None)?;
    let mut out = SecretBytes::zeroed(n);
    inflate(data, limit, Some(out.expose_mut()))?;
    Ok(out)
}

/// One pass over a gzip member; copies the output into `out` when given.
fn inflate(data: &[u8], limit: usize, mut out: Option<&mut [u8]>) -> Result<usize, Error> {
    let body = data.get(gzip_header_len(data)?..).ok_or(Error::Corrupt)?;
    let mut d = Decompress::new(false);
    let mut crc = Crc::new();
    let mut scratch = SecretBytes::zeroed(PIECE);
    let mut produced: usize = 0;
    loop {
        let (in_before, out_before) = (d.total_in(), d.total_out());
        let input = body.get(as_usize(in_before)?..).ok_or(Error::Corrupt)?;
        let status = d
            .decompress(input, scratch.expose_mut(), FlushDecompress::None)
            .map_err(|_| Error::Corrupt)?;
        let wrote = as_usize(d.total_out().saturating_sub(out_before))?;
        let chunk = scratch.expose().get(..wrote).ok_or(Error::Corrupt)?;
        crc.update(chunk);
        let end = produced
            .checked_add(wrote)
            .ok_or(Error::TooLarge(Limit::Total))?;
        if end > limit {
            return Err(Error::TooLarge(Limit::Total));
        }
        if let Some(out) = out.as_deref_mut() {
            out.get_mut(produced..end)
                .ok_or(Error::Corrupt)?
                .copy_from_slice(chunk);
        }
        produced = end;
        match status {
            Status::StreamEnd => break,
            _ if wrote == 0 && d.total_in() == in_before => return Err(Error::Corrupt),
            _ => {}
        }
    }
    let trailer = body.get(as_usize(d.total_in())?..).ok_or(Error::Corrupt)?;
    let trailer: [u8; 8] = trailer.try_into().map_err(|_| Error::Corrupt)?; // LD-02: nothing after
    let [c0, c1, c2, c3, s0, s1, s2, s3] = trailer;
    let size_ok = u32::from_le_bytes([s0, s1, s2, s3]) == crc.amount();
    if u32::from_le_bytes([c0, c1, c2, c3]) != crc.sum() || !size_ok {
        return Err(Error::Corrupt);
    }
    Ok(produced)
}

fn as_usize(n: u64) -> Result<usize, Error> {
    usize::try_from(n).map_err(|_| Error::Corrupt)
}

/// The length of the gzip member header (RFC 1952 section 2.3, FMT-08.6).
fn gzip_header_len(data: &[u8]) -> Result<usize, Error> {
    const FHCRC: u8 = 0x02;
    const FEXTRA: u8 = 0x04;
    const FNAME: u8 = 0x08;
    const FCOMMENT: u8 = 0x10;
    let (head, _) = data.split_first_chunk::<10>().ok_or(Error::Corrupt)?;
    let [id1, id2, cm, flg, ..] = *head;
    if (id1, id2, cm) != (0x1F, 0x8B, 0x08) || flg & 0xE0 != 0 {
        return Err(Error::Corrupt);
    }
    let mut pos: usize = 10;
    let at = |pos: usize| data.get(pos..).ok_or(Error::Corrupt);
    if flg & FEXTRA != 0 {
        let (xlen, _) = at(pos)?.split_first_chunk::<2>().ok_or(Error::Corrupt)?;
        pos = pos
            .checked_add(2)
            .and_then(|p| p.checked_add(usize::from(u16::from_le_bytes(*xlen))))
            .ok_or(Error::Corrupt)?;
    }
    for flag in [FNAME, FCOMMENT] {
        if flg & flag != 0 {
            let zero = at(pos)?
                .iter()
                .position(|&b| b == 0)
                .ok_or(Error::Corrupt)?;
            pos = pos
                .checked_add(zero)
                .and_then(|p| p.checked_add(1))
                .ok_or(Error::Corrupt)?;
        }
    }
    if flg & FHCRC != 0 {
        let (stored, _) = at(pos)?.split_first_chunk::<2>().ok_or(Error::Corrupt)?;
        let mut crc = Crc::new();
        crc.update(data.get(..pos).ok_or(Error::Corrupt)?);
        if u32::from(u16::from_le_bytes(*stored)) != crc.sum() & 0xFFFF {
            return Err(Error::Corrupt);
        }
        pos = pos.checked_add(2).ok_or(Error::Corrupt)?;
    }
    if pos > data.len() {
        return Err(Error::Corrupt);
    }
    Ok(pos)
}

/// Test probe: how often this thread ran the KDF, the decryptor and the
/// decompressor, and how many bytes it decrypted, so tests can prove a step
/// never ran ("spy" rows of the cards; LD-78). Counting only; it changes
/// nothing and holds no data.
#[doc(hidden)]
pub mod probe {
    use core::cell::Cell;

    /// Calls since the last [`take`].
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Counts {
        /// KDF runs on a composite key.
        pub kdf: usize,
        /// Payload decryptions started.
        pub decrypt: usize,
        /// Gunzip calls.
        pub inflate: usize,
        /// Plaintext bytes the decryptor handed back.
        pub decrypted: usize,
    }

    thread_local! {
        static COUNTS: Cell<Counts> = const {
            Cell::new(Counts { kdf: 0, decrypt: 0, inflate: 0, decrypted: 0 })
        };
    }

    pub(crate) fn count(f: impl FnOnce(&mut Counts)) {
        COUNTS.with(|c| {
            let mut v = c.get();
            f(&mut v);
            c.set(v);
        });
    }

    /// Returns the counts of this thread and resets them.
    #[must_use]
    pub fn take() -> Counts {
        COUNTS.with(Cell::take)
    }
}

/// The gzip member header App writes (FMT-08.9): no flags, modification
/// time 0, XFL 0, OS `13`.
const GZIP_HEADER: [u8; 10] = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13];

/// Gzips `data` as one member (FMT-08.9): the header above, deflate at level
/// 6, CRC32 and ISIZE little-endian. The output goes into a wiping buffer.
///
/// Limit: the deflate state inside flate2 holds up to 32 KiB of input and
/// is freed without a wipe; the crate offers no way to wipe it.
///
/// # Errors
/// `Corrupt` only if the deflate engine reports an error, which it does not
/// for in-memory input.
pub(crate) fn gzip(data: &[u8]) -> Result<Grow, Error> {
    let mut out = Grow::new();
    out.extend(&GZIP_HEADER);
    let mut c = Compress::new(flate2::Compression::new(6), false);
    let mut scratch = SecretBytes::zeroed(PIECE);
    loop {
        let (in_before, out_before) = (c.total_in(), c.total_out());
        let input = data.get(as_usize(in_before)?..).ok_or(Error::Corrupt)?;
        let status = c
            .compress(input, scratch.expose_mut(), FlushCompress::Finish)
            .map_err(|_| Error::Corrupt)?;
        let wrote = as_usize(c.total_out().saturating_sub(out_before))?;
        out.extend(scratch.expose().get(..wrote).ok_or(Error::Corrupt)?);
        match status {
            Status::StreamEnd => break,
            _ if wrote == 0 && c.total_in() == in_before => return Err(Error::Corrupt),
            _ => {}
        }
    }
    let mut crc = Crc::new();
    crc.update(data);
    out.extend(&crc.sum().to_le_bytes());
    out.extend(&crc.amount().to_le_bytes());
    Ok(out)
}

/// Encrypts `plain` as one stream (FMT-08.10 step 3): CBC pads once at the
/// end. The ciphertext is public.
///
/// # Errors
/// `Corrupt` only for a key or IV of the wrong length, which the caller
/// rules out.
pub(crate) fn encrypt(
    cipher: Cipher,
    key: &SecretBytes,
    iv: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut enc = Encryptor::new(cipher, key, iv).map_err(|_| Error::Corrupt)?;
    let mut out = Vec::with_capacity(plain.len().saturating_add(16));
    for piece in plain.chunks(PIECE) {
        out.extend_from_slice(&enc.update(piece).map_err(|_| Error::Corrupt)?);
    }
    out.extend_from_slice(&enc.finish());
    Ok(out)
}
