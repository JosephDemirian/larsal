//! The signed wrap record on the wire (CRY-04.6, CRY-05.4, SYN-01.10,
//! SYN-01.16): one JSON record of at most [`MAX_WRAP`] bytes (16 KiB,
//! CRY-05.14),
//! `{"suite":[kem,kdf,aead],"enc":…,"ct":…,"info":…,"signer":…,"signature":…}`,
//! byte strings in base64url, the signer as an id.
//!
//! Guarantees: [`read`] refuses a record over [`MAX_WRAP`] before one byte
//! of it is parsed, so such a record never becomes a [`WrapRecord`] and
//! never reaches `larsal_crypto::wrap_record::open`; a record whose enc or
//! signature has another size than the hybrid suite's (a classical record
//! of CRY-04.5 among them) is refused here too. Opening (suite, info,
//! signature, then hybrid HPKE) is larsal-crypto's.

use crate::Error;
use crate::limits::MAX_WRAP;
use crate::messages::{Id, b64, byte_string, id, read_record, write};
use larsal_crypto::pq::{ENC, MAX_INFO, MAX_PLAINTEXT, SIGNATURE};
use larsal_crypto::wrap_record::WrapRecord;
use larsal_model::json::Value;

/// Reads a wrap record of at most [`MAX_WRAP`] bytes.
///
/// # Errors
/// [`Error::TooLarge`] over [`MAX_WRAP`], before anything is parsed; else
/// as [`read_record`], or a missing or invalid field: a suite that is not
/// three numbers up to 65,535, an enc of other than 1,120 bytes, a ct of
/// other than 16 to 1,040 bytes, an info over 512 bytes, a signature of
/// other than 3,373 bytes.
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
        enc: byte_string(&map, "enc", ENC..=ENC)?,
        ct: byte_string(&map, "ct", ct_len)?,
        info: byte_string(&map, "info", 0..=MAX_INFO)?,
        signer: *id(&map, "signer")?.as_bytes(),
        signature: byte_string(&map, "signature", SIGNATURE..=SIGNATURE)?,
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
    use larsal_crypto::pq::{identity_keypair, xwing_keypair};
    use larsal_crypto::wrap_record::{make, open};

    /// Pads a record's JSON with spaces before its last byte to `len` bytes.
    fn pad(b: &mut Vec<u8>, len: usize) {
        let end = b.pop().unwrap();
        b.resize(len.saturating_sub(1), b' ');
        b.push(end);
    }

    /// CRY-05.14, CRY-05 T25, SYN-01.16: the exact sizes on the wire of the
    /// hybrid records this story makes (a 32-byte key with a 90-byte info,
    /// the smallest, and the largest: info 512, plaintext 1 KiB); a valid
    /// record of exactly 16 KiB is read and opens; one byte more is refused
    /// as too large before it is parsed, so it never reaches
    /// `wrap_record::open`, which would have opened it.
    #[test]
    fn cry05_14_t25_wrap_record_sizes_and_the_16_kib_limit() {
        let (seed, public) = xwing_keypair().unwrap();
        let (identity, identity_public) = identity_keypair().unwrap();
        for (info, plaintext, size) in [
            (90, 32, 6283),
            (0, 0, 6121),
            (MAX_INFO, MAX_PLAINTEXT, 8169),
        ] {
            let record = make(
                &public,
                &vec![1; info],
                &vec![2; plaintext],
                [6; 16],
                &identity,
            )
            .unwrap();
            assert_eq!(
                to_json(&record).len(),
                size,
                "info {info}, plaintext {plaintext}"
            );
        }
        let info = vec![1u8; MAX_INFO];
        let plaintext = vec![2u8; MAX_PLAINTEXT];
        let record = make(&public, &info, &plaintext, [6; 16], &identity).unwrap();
        let mut bytes = to_json(&record);
        pad(&mut bytes, MAX_WRAP);
        assert_eq!(bytes.len(), 16_384);
        let read_back = read(&bytes).unwrap();
        assert_eq!(read_back, record);
        let opened = open(&read_back, &identity_public, &info, &seed).unwrap();
        assert_eq!(opened.expose(), plaintext.as_slice());
        pad(&mut bytes, MAX_WRAP + 1);
        assert_eq!(read(&bytes), Err(Error::TooLarge));
        // Before parsing: 16 KiB + 1 byte that is no JSON at all.
        assert_eq!(read(&vec![b'x'; MAX_WRAP + 1]), Err(Error::TooLarge));
        assert_eq!(read(&vec![b'x'; MAX_WRAP]), Err(Error::NotJson));
    }

    /// CRY-04.6's fields with CRY-05.4's sizes, each refused when it has the
    /// wrong form; a classical record (CRY-04.5's sizes, CRY-05.7) is
    /// refused at its enc.
    #[test]
    fn cry04_6_wrap_record_fields() {
        let record = WrapRecord {
            suite: [25722, 1, 3],
            enc: vec![1; 1120],
            ct: vec![2; 48],
            info: b"info".to_vec(),
            signer: [3; 16],
            signature: vec![4; 3373],
        };
        let json = String::from_utf8(to_json(&record)).unwrap();
        assert!(json.contains(r#""suite":[25722,1,3]"#), "{json}");
        assert!(json.contains(&format!(r#""signer":"{}""#, "03".repeat(16))));
        assert_eq!(read(json.as_bytes()), Ok(record.clone()));
        // Another suite reads: wrap_record::open refuses it at its step 1.
        let other = json.replace("[25722,1,3]", "[32,1,2]");
        assert_eq!(read(other.as_bytes()).unwrap().suite, [32, 1, 2]);
        for (from, to, field) in [
            ("[25722,1,3]", "[25722,1]", "suite"),
            ("[25722,1,3]", "[25722,1,3,4]", "suite"),
            ("[25722,1,3]", "[25722,1,65536]", "suite"),
            ("[25722,1,3]", "[25722,1,\"3\"]", "suite"),
            ("[25722,1,3]", "25722", "suite"),
            (&b64(&[1; 1120]), &b64(&[1; 1119]), "enc"),
            (&b64(&[1; 1120]), &b64(&[1; 1121]), "enc"),
            (&b64(&[1; 1120]), &b64(&[1; 32]), "enc"),
            (&b64(&[2; 48]), &b64(&[2; 15]), "ct"),
            (&b64(&[2; 48]), &b64(&[2; 1041]), "ct"),
            ("\"aW5mbw\"", &format!("\"{}\"", b64(&[0; 513])), "info"),
            (&"03".repeat(16), &"03".repeat(15), "signer"),
            (&b64(&[4; 3373]), &b64(&[4; 3372]), "signature"),
            (&b64(&[4; 3373]), &b64(&[4; 64]), "signature"),
        ] {
            let bad = json.replacen(from, to, 1);
            assert_ne!(bad, json, "{from}");
            assert_eq!(read(bad.as_bytes()), Err(Error::Invalid(field)), "{to}");
        }
        assert_eq!(read(b"{}"), Err(Error::Missing("suite")));
    }

    /// CRY-05.7: a record left in CRY-04.5's classical form (suite
    /// [32, 1, 2], a 32-byte enc, a 64-byte Ed25519 signature) never reads,
    /// so it never reaches the opener; one relabelled to the hybrid suite
    /// does not read either.
    #[test]
    fn cry05_7_a_classical_record_is_refused() {
        let mut fields = vec![
            ("suite", "[32,1,2]".to_owned()),
            ("enc", format!("\"{}\"", b64(&[1; 32]))),
            ("ct", format!("\"{}\"", b64(&[2; 48]))),
            ("info", "\"aW5mbw\"".to_owned()),
            ("signer", format!("\"{}\"", "03".repeat(16))),
            ("signature", format!("\"{}\"", b64(&[4; 64]))),
        ];
        let json = |fields: &[(&str, String)]| {
            let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
            format!("{{{}}}", body.join(","))
        };
        assert_eq!(read(json(&fields).as_bytes()), Err(Error::Invalid("enc")));
        fields[0].1 = "[25722,1,3]".to_owned();
        assert_eq!(read(json(&fields).as_bytes()), Err(Error::Invalid("enc")));
        fields[1].1 = format!("\"{}\"", b64(&[1; 1120]));
        assert_eq!(
            read(json(&fields).as_bytes()),
            Err(Error::Invalid("signature"))
        );
    }
}
