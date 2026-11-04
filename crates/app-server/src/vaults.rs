//! The vault routes (SYN-01.6; P1, P3): `GET /v1/vaults`, and `GET` and
//! `PUT /v1/vaults/{vault_id}` with the ETag rules of RFC 9110, on the
//! files and rows of [`Blobs`]. The server never reads the bytes beyond
//! their length (P16). Each runs for the caller's account (E16-S5): a
//! vault of another account is one that does not exist (404 on a GET, 412
//! on a PUT), and the list holds only the caller's vaults.
//!
//! A PUT, in this order: no `Content-Length` (none, or a chunked body)
//! gets 411; then the precondition (428 or 400,
//! [`routes::put_precondition`]); then a cheap look at the current version,
//! so a stale upload gets 412 before one body byte is read; then the body
//! streams into a temp file, counted and hashed as it arrives, and is
//! flushed to the device; then the commit's compare-and-swap decides
//! (SYN-02.4). A body cut off, timed out or longer than it said stores
//! nothing. Each store call runs on tokio's blocking pool, so the one
//! writer lock never stops the event loop.

use crate::Error;
use crate::blobs::Blobs;
use crate::http::{Body, blocking, error, failed, reply};
use crate::store::Cas;
use app_crypto::hash::{Algorithm, Hasher};
use app_proto::messages::{AccountId, ErrorCode, VaultId, VaultVersion, vault_list};
use app_proto::routes::{self, Precondition, PreconditionError};
use http_body_util::{BodyExt, Either};
use hyper::body::{Body as _, Bytes, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};

fn with_etag(mut r: Response<Body>, version: u64) -> Response<Body> {
    if let Ok(tag) = HeaderValue::from_str(&routes::etag(version)) {
        r.headers_mut().insert(header::ETAG, tag);
    }
    r
}

/// Every field line of `name`, as bytes.
fn lines<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Vec<&'a [u8]> {
    headers
        .get_all(name)
        .iter()
        .map(HeaderValue::as_bytes)
        .collect()
}

/// `GET /v1/vaults`: `{"vaults":[{"id":…,"version":…,"size":…}]}`, the
/// account's vaults sorted by id.
// ponytail: the list is not checked against SYN-01.10's 1 MiB reply limit;
// it holds 11,000 vaults, and quotas come with E19 (LD-321 (7)).
pub(crate) async fn list(blobs: &Arc<Blobs>, account: AccountId) -> Response<Body> {
    let b = blobs.clone();
    match blocking(move || b.list(&account)).await {
        Ok(vaults) => reply(StatusCode::OK, vault_list(&vaults)),
        Err(e) => failed(&e),
    }
}

/// `GET /v1/vaults/{vault_id}`: 200 with the bytes as uploaded, or 304
/// when `If-None-Match` names the current version; 404 for an unknown id
/// and for another account's vault alike.
pub(crate) async fn get(
    headers: &HeaderMap,
    id: VaultId,
    account: AccountId,
    blobs: &Arc<Blobs>,
) -> Response<Body> {
    let b = blobs.clone();
    let (row, file) = match blocking(move || b.read(&id)).await {
        Ok(Some(found)) if found.0.account == account => found,
        Ok(_) => return error(StatusCode::NOT_FOUND, ErrorCode::NotFound),
        Err(e) => return failed(&e),
    };
    if routes::not_modified(&lines(headers, &header::IF_NONE_MATCH), row.version) {
        return with_etag(reply(StatusCode::NOT_MODIFIED, Vec::new()), row.version);
    }
    let mut r = Response::new(Either::Right(FileBody {
        file: tokio::fs::File::from_std(file),
        left: row.size,
        buf: vec![0u8; CHUNK].into_boxed_slice(),
    }));
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(row.size));
    with_etag(r, row.version)
}

/// `PUT /v1/vaults/{vault_id}`: 201 for a new vault, 200 for an update,
/// each with the new `ETag` and `{"id":…,"version":…,"size":…}`.
pub(crate) async fn put(
    headers: &HeaderMap,
    body: &mut Incoming,
    id: VaultId,
    account: AccountId,
    blobs: &Arc<Blobs>,
) -> Response<Body> {
    // 411 first: without the preconditions the reply would be 411 too
    // (RFC 9110 section 13.2.1). hyper reads a request with neither header
    // as a body of 0 bytes (RFC 9112 section 6.3), so the header itself
    // must be there; hyper drops a `Content-Length` sent with
    // `Transfer-Encoding: chunked`, so that body fails this check too.
    let (true, Some(length)) = (
        headers.contains_key(header::CONTENT_LENGTH),
        body.size_hint().exact(),
    ) else {
        return error(StatusCode::LENGTH_REQUIRED, ErrorCode::LengthRequired);
    };
    let want = match routes::put_precondition(
        &lines(headers, &header::IF_MATCH),
        &lines(headers, &header::IF_NONE_MATCH),
    ) {
        Ok(want) => want,
        Err(PreconditionError::Required) => {
            return error(
                StatusCode::PRECONDITION_REQUIRED,
                ErrorCode::PreconditionRequired,
            );
        }
        Err(PreconditionError::Bad) => {
            return error(StatusCode::BAD_REQUEST, ErrorCode::BadRequest);
        }
    };
    let b = blobs.clone();
    let now = match blocking(move || b.current(&id)).await {
        Ok(row) => row,
        Err(e) => return failed(&e),
    };
    // A new vault needs an id no account has; an update, this account's
    // vault at the named version.
    let may = match (want, now) {
        (Precondition::Create, row) => row.is_none(),
        (Precondition::Update(version), Some(row)) => {
            row.account == account && version == Some(row.version)
        }
        (Precondition::Update(_), None) => false,
    };
    if !may {
        return precondition_failed();
    }
    let (temp, hash) = match receive(body, length, blobs).await {
        Ok(Some(done)) => done,
        Ok(None) => return error(StatusCode::BAD_REQUEST, ErrorCode::BadRequest),
        Err(e) => return failed(&e),
    };
    let b = blobs.clone();
    match blocking(move || b.commit(&id, &account, want, temp, hash, length)).await {
        Ok(Cas::Done(version)) => {
            let status = match want {
                Precondition::Create => StatusCode::CREATED,
                Precondition::Update(_) => StatusCode::OK,
            };
            let made = VaultVersion {
                id,
                version,
                size: length,
            };
            with_etag(reply(status, made.to_json()), version)
        }
        Ok(Cas::Conflict) => precondition_failed(),
        Err(e) => failed(&e),
    }
}

fn precondition_failed() -> Response<Body> {
    error(
        StatusCode::PRECONDITION_FAILED,
        ErrorCode::PreconditionFailed,
    )
}

/// SYN-02.4 steps 1 and 2: streams the body into a new temp file, counting
/// and hashing as the bytes arrive, then flushes it to the device (std's
/// `sync_all` is `F_FULLFSYNC` on macOS). `Ok(None)` when the body was cut
/// off, timed out, or did not have `length` bytes; the temp file is then
/// deleted (dropped).
async fn receive(
    body: &mut Incoming,
    length: u64,
    blobs: &Arc<Blobs>,
) -> Result<Option<(crate::blobs::Temp, [u8; 32])>, Error> {
    let b = blobs.clone();
    let (temp, file) = blocking(move || b.temp()).await?;
    let mut file = tokio::fs::File::from_std(file);
    let written = |e: io::Error| Error::new(format!("cannot write a vault file: {e}"));
    let mut hasher = Hasher::new(Algorithm::Sha256);
    let mut count = 0u64;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            return Ok(None);
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        count = count.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if count > length {
            return Ok(None);
        }
        hasher.update(&data);
        file.write_all(&data).await.map_err(written)?;
    }
    if count != length {
        return Ok(None);
    }
    file.flush().await.map_err(written)?;
    file.sync_all().await.map_err(written)?;
    let digest = hasher.finalize();
    let hash = <[u8; 32]>::try_from(digest.expose())
        .map_err(|_| Error::new("a SHA-256 that is not 32 bytes"))?;
    Ok(Some((temp, hash)))
}

/// The bytes a GET streams per frame.
const CHUNK: usize = 64 * 1024;

/// A vault file streamed from its open handle (SYN-02.7): exactly the row's
/// size, so a later commit that deletes the file's name does not cut it.
pub(crate) struct FileBody {
    file: tokio::fs::File,
    left: u64,
    buf: Box<[u8]>,
}

impl hyper::body::Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        let want = usize::try_from(this.left)
            .unwrap_or(usize::MAX)
            .min(this.buf.len());
        let Some(space) = this.buf.get_mut(..want).filter(|s| !s.is_empty()) else {
            return Poll::Ready(None);
        };
        let mut read = ReadBuf::new(space);
        match Pin::new(&mut this.file).poll_read(cx, &mut read) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            Poll::Ready(Ok(())) if read.filled().is_empty() => {
                Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())))
            }
            Poll::Ready(Ok(())) => {
                let got = read.filled();
                this.left = this
                    .left
                    .saturating_sub(u64::try_from(got.len()).unwrap_or(u64::MAX));
                Poll::Ready(Some(Ok(Frame::data(Bytes::copy_from_slice(got)))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.left == 0
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.left)
    }
}
