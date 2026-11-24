//! The signed wrap record on the wire (CRY-04.6, SYN-01.10; LD-305 (5)):
//! one JSON record of at most [`MAX_WRAP`] bytes,
//! `{"suite":[kem,kdf,aead],"enc":…,"ct":…,"info":…,"signer":…,"signature":…}`,
//! byte strings in base64url, the signer as an id.
//!
//! Guarantees: [`read`] refuses a record over [`MAX_WRAP`] before one byte
//! of it is parsed, so such a record never becomes a [`WrapRecord`] and
//! never reaches `larsal_crypto::hpke::open_wrap`. Opening (suite, info,
//! signature, then HPKE) is larsal-crypto's.

use crate::Error;
use crate::limits::MAX_WRAP;
use crate::messages::{Id, array, b64, byte_string, id, read_record, write};
use larsal_crypto::hpke::WrapRecord;
use larsal_model::json::Value;

/// The largest HPKE plaintext (CRY-04's input table): 1 KiB.
const MAX_PLAINTEXT: usize = 1024;
/// The largest HPKE info (CRY-04's input table).
const MAX_INFO: usize = 512;

/// Reads a wrap record of at most [`MAX_WRAP`] bytes.
///
/// # Errors
/// [`Error::TooLarge`] over [`MAX_WRAP`], before anything is parsed; else
/// as [`read_record`], or a missing or invalid field: a suite that is not
/// three numbers up to 65,535, an enc of other than 32 bytes, a ct of other
/// than 16 to 1,040 bytes, an info over 512 bytes, a signature of other
/// than 64 bytes.
pub fn read(bytes: &[u8]) -> Result<WrapRecord, Error> {
    let map = read_record(bytes, MAX_WRAP)?;
    let suite = map
        .get("suite")
        .ok_or(Error::Missing("suite"))?
        .as_array()
        .and_then(|items| {
            let ids: Vec<u16> = items
                .iter()
                .filter_map(|n| n.as_u64().and_then(|n| u16::try_from(n).ok()))
                .collect();
            <[u16; 3]>::try_from(ids).ok().filter(|_| items.len() == 3)
        })
        .ok_or(Error::Invalid("suite"))?;
    let ct_len = 16..=MAX_PLAINTEXT.saturating_add(16);
    Ok(WrapRecord {
        suite,
        enc: array::<32>(&map, "enc")?.to_vec(),
        ct: byte_string(&map, "ct", ct_len)?,
        info: byte_string(&map, "info", 0..=MAX_INFO)?,
        signer: *id(&map, "signer")?.as_bytes(),
        signature: array::<64>(&map, "signature")?.to_vec(),
    })
}

/// The record's bytes.
#[must_use]
pub fn to_json(record: &WrapRecord) -> Vec<u8> {
    let suite: Vec<Value> = record
        .suite
        .iter()
        .map(|n| Value::from(u32::from(*n)))
        .collect();
    write(&larsal_model::json!({
        "suite": suite,
        "enc": b64(&record.enc),
        "ct": b64(&record.ct),
        "info": b64(&record.info),
        "signer": Id::from_bytes(record.signer).to_string(),
        "signature": b64(&record.signature)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use larsal_crypto::hpke::{make_wrap, open_wrap, x25519_keypair};
    use larsal_crypto::secret::SecretBytes;
    use larsal_crypto::sign::ed25519_public;

    /// LD-305 (5), SYN-01.10: a valid record of exactly 4 KiB is read and
    /// opens; the same record one byte over 4 KiB is refused as too large
    /// before it is parsed, so it never reaches `open_wrap`, which would
    /// have opened it.
    #[test]
    fn ld305_5_wrap_record_over_4_kib_never_reaches_open_wrap() {
        let (private, public) = x25519_keypair().unwrap();
        let seed = SecretBytes::new(vec![5; 32]);
        let info = vec![1u8; MAX_INFO];
        let plaintext = vec![2u8; MAX_PLAINTEXT];
        let record = make_wrap(&public, &info, &plaintext, [6; 16], &seed).unwrap();
        let mut bytes = to_json(&record);
        // CRY-04's largest wrap fits with room to spare (SYN-01.10).
        assert!(bytes.len() < 3 * 1024, "{}", bytes.len());
        let pad = |b: &mut Vec<u8>, len: usize| {
            let end = b.pop().unwrap();
            b.resize(len - 1, b' ');
            b.push(end);
        };
        pad(&mut bytes, MAX_WRAP);
        let signer = ed25519_public(&seed).unwrap();
        let read_back = read(&bytes).unwrap();
        assert_eq!(read_back, record);
        let opened = open_wrap(&read_back, &signer, &info, &private).unwrap();
        assert_eq!(opened.expose(), plaintext.as_slice());
        pad(&mut bytes, MAX_WRAP + 1);
        assert_eq!(read(&bytes), Err(Error::TooLarge));
    }

    /// CRY-04.6's fields, each refused when it has the wrong form.
    #[test]
    fn cry04_6_wrap_record_fields() {
        let record = WrapRecord {
            suite: [0x20, 1, 2],
            enc: vec![1; 32],
            ct: vec![2; 48],
            info: b"info".to_vec(),
            signer: [3; 16],
            signature: vec![4; 64],
        };
        let json = String::from_utf8(to_json(&record)).unwrap();
        assert!(json.contains(r#""suite":[32,1,2]"#), "{json}");
        assert!(json.contains(&format!(r#""signer":"{}""#, "03".repeat(16))));
        assert_eq!(read(json.as_bytes()), Ok(record.clone()));
        // Another suite reads: open_wrap refuses it at its step 1.
        let other = json.replace("[32,1,2]", "[32,1,3]");
        assert_eq!(read(other.as_bytes()).unwrap().suite, [32, 1, 3]);
        for (from, to, field) in [
            ("[32,1,2]", "[32,1]", "suite"),
            ("[32,1,2]", "[32,1,2,4]", "suite"),
            ("[32,1,2]", "[32,1,65536]", "suite"),
            ("[32,1,2]", "[32,1,\"2\"]", "suite"),
            ("[32,1,2]", "32", "suite"),
            (&b64(&[1; 32]), &b64(&[1; 31]), "enc"),
            (&b64(&[2; 48]), &b64(&[2; 15]), "ct"),
            (&b64(&[2; 48]), &b64(&[2; 1041]), "ct"),
            ("\"aW5mbw\"", &format!("\"{}\"", b64(&[0; 513])), "info"),
            (&"03".repeat(16), &"03".repeat(15), "signer"),
            (&b64(&[4; 64]), &b64(&[4; 63]), "signature"),
        ] {
            let bad = json.replacen(from, to, 1);
            assert_ne!(bad, json, "{from}");
            assert_eq!(read(bad.as_bytes()), Err(Error::Invalid(field)), "{to}");
        }
        assert_eq!(read(b"{}"), Err(Error::Missing("suite")));
    }
}
