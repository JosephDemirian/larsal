//! Story check 3, FIL-03-T04 and FIL-03-T16: one changed, cut or swapped byte
//! anywhere gives the one generic error and no plaintext. Exhaustive on small
//! files, sampled on larger ones, in both modes and in armor.

use super::*;
use crate::limits::{CHUNK, SEALED_CHUNK};

fn x_keys() -> Identities {
    ids(ID_A)
}

/// Every single-bit change of every byte, every cut, and extra bytes at every length.
fn exhaustive(good: &[u8], unlock: &Unlock<'_>, plain: &[u8]) {
    assert_eq!(open(good, unlock).unwrap(), plain);
    for at in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.to_vec();
            bad[at] ^= 1 << bit;
            refused(&bad, unlock);
        }
    }
    for cut in 0..good.len() {
        refused(&good[..cut], unlock);
    }
    for extra in 1..=64 {
        let mut long = good.to_vec();
        long.extend(vec![0u8; extra]);
        refused(&long, unlock);
    }
}

#[test]
fn check3_every_bit_and_cut_of_a_small_x25519_file() {
    let keys = x_keys();
    exhaustive(
        &seal_to(PLAIN, &[rec(ID_A)]),
        &Unlock::Identities(&keys),
        PLAIN,
    );
    exhaustive(&seal_to(b"", &[rec(ID_A)]), &Unlock::Identities(&keys), b"");
}

#[test]
fn check3_every_bit_and_cut_of_a_small_passphrase_file() {
    let phrase = secret(PASS);
    let file = seal_cost(PLAIN, PASS, 1);
    exhaustive(&file, &Unlock::Passphrase(&phrase), PLAIN);
}

#[test]
fn check3_every_bit_and_cut_of_a_small_armored_file() {
    let keys = x_keys();
    let unlock = Unlock::Identities(&keys);
    let good = armor(&seal_to(PLAIN, &[rec(ID_A)]), "\n");
    assert_eq!(open(&good, &unlock).unwrap(), PLAIN);
    for at in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[at] ^= 1 << bit;
            refused(&bad, &unlock);
        }
    }
    // The newline ending the END line is optional transport: a cut there opens.
    for cut in 0..good.len() - 1 {
        refused(&good[..cut], &unlock);
    }
    assert_eq!(open(&good[..good.len() - 1], &unlock).unwrap(), PLAIN);
}

/// A three chunk file, its header's length and the offset of chunk `n`.
fn larger(plain: &[u8]) -> (Vec<u8>, usize) {
    let file = seal_to(plain, &[rec(ID_A)]);
    let head = header_end(&file) + 16;
    (file, head)
}

fn plain_3() -> Vec<u8> {
    demo_bytes(2 * CHUNK + 1234)
}

#[test]
fn check3_every_header_byte_and_chunk_boundary_of_a_larger_file() {
    let keys = x_keys();
    let unlock = Unlock::Identities(&keys);
    let plain = plain_3();
    let (good, payload) = larger(&plain);
    assert_eq!(open(&good, &unlock).unwrap(), plain);
    // Every byte of the header and the nonce, at every bit.
    for at in 0..payload {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[at] ^= 1 << bit;
            refused(&bad, &unlock);
        }
    }
    // Around each boundary: both sides, change and cut.
    for boundary in [SEALED_CHUNK, 2 * SEALED_CHUNK, good.len() - payload] {
        for at in boundary - 3..(boundary + 3).min(good.len() - payload) {
            let mut bad = good.clone();
            bad[payload + at] ^= 0x80;
            assert_eq!(refused(&bad, &unlock), Failure::Payload, "at {at}");
        }
        for cut in boundary - 3..=(boundary + 3).min(good.len() - payload - 1) {
            let keep_to = payload + cut;
            if keep_to < good.len() {
                assert_eq!(
                    refused(&good[..keep_to], &unlock),
                    Failure::Payload,
                    "cut {cut}"
                );
            }
        }
    }
    // Cutting exactly on a chunk boundary removes the final marker.
    assert_eq!(
        refused(&good[..payload + SEALED_CHUNK], &unlock),
        Failure::Payload
    );
    assert_eq!(
        refused(&good[..payload + 2 * SEALED_CHUNK], &unlock),
        Failure::Payload
    );
}

#[test]
fn check3_swapped_removed_repeated_and_spliced_chunks() {
    let keys = x_keys();
    let unlock = Unlock::Identities(&keys);
    let plain = plain_3();
    let (good, payload) = larger(&plain);
    let (head, body) = good.split_at(payload);
    let parts: Vec<&[u8]> = body.chunks(SEALED_CHUNK).collect();
    assert_eq!(parts.len(), 3);
    let join = |order: &[&[u8]]| [head, &order.concat()].concat();
    for (name, order) in [
        ("swap 0 1", vec![parts[1], parts[0], parts[2]]),
        ("swap 1 2", vec![parts[0], parts[2], parts[1]]),
        ("swap 0 2", vec![parts[2], parts[1], parts[0]]),
        ("no first", vec![parts[1], parts[2]]),
        ("no middle", vec![parts[0], parts[2]]),
        ("no last", vec![parts[0], parts[1]]),
        ("first twice", vec![parts[0], parts[0], parts[1], parts[2]]),
        ("last twice", vec![parts[0], parts[1], parts[2], parts[2]]),
        ("middle twice", vec![parts[0], parts[1], parts[1], parts[2]]),
    ] {
        assert_eq!(refused(&join(&order), &unlock), Failure::Payload, "{name}");
    }

    // A chunk of another file, under the same recipient: its position is right
    // and its key is not.
    let (other, other_payload) = larger(&plain);
    let other_parts: Vec<&[u8]> = other[other_payload..].chunks(SEALED_CHUNK).collect();
    let spliced = join(&[parts[0], other_parts[1], parts[2]]);
    assert_eq!(refused(&spliced, &unlock), Failure::Payload);
    // Another file's whole payload under this header, and the other way round.
    let swapped_payload = [head, &other[other_payload..]].concat();
    assert_eq!(refused(&swapped_payload, &unlock), Failure::Payload);
    // Another file's header and this file's payload.
    let swapped_header = [&other[..other_payload], body].concat();
    assert_eq!(refused(&swapped_header, &unlock), Failure::Payload);
}

#[test]
fn check3_final_marker_and_trailing_bytes() {
    let keys = x_keys();
    let unlock = Unlock::Identities(&keys);
    let file_key = demo_file_key();
    let key = payload_key(&file_key, &NONCE);
    let head = sealed_header(&file_key, &x_stanza(&file_key, &rec(ID_A), 7));
    let with = |body: Vec<u8>| [head.clone(), NONCE.to_vec(), body].concat();
    let full = demo_bytes(CHUNK);

    // The control: the same pieces, in the right form, open.
    assert_eq!(
        open(&with(chunk(&key, 0, true, PLAIN)), &unlock).unwrap(),
        PLAIN
    );
    assert_eq!(
        open(&with(chunk(&key, 0, true, &full)), &unlock).unwrap(),
        full
    );
    assert_eq!(
        open(&with(chunk(&key, 0, true, b"")), &unlock).unwrap(),
        b""
    );

    // Final flag missing at the end, final flag early, on an empty and on a full chunk.
    for body in [
        chunk(&key, 0, false, PLAIN),
        chunk(&key, 0, false, &full),
        chunk(&key, 0, false, b""),
        [chunk(&key, 0, false, &full), chunk(&key, 1, false, PLAIN)].concat(),
        [chunk(&key, 0, true, &full), chunk(&key, 1, true, PLAIN)].concat(),
    ] {
        assert_eq!(refused(&with(body), &unlock), Failure::Payload);
    }
    // An empty last chunk after others, even with a right tag and flag.
    let empty_last = [chunk(&key, 0, false, &full), chunk(&key, 1, true, b"")].concat();
    assert_eq!(refused(&with(empty_last), &unlock), Failure::Payload);
    // A nonce cut short or missing is the header stage; no chunk at all is not.
    for cut in [15, 0] {
        assert_eq!(
            refused(&[head.clone(), NONCE[..cut].to_vec()].concat(), &unlock),
            Failure::Header
        );
    }
    assert_eq!(refused(&with(Vec::new()), &unlock), Failure::Payload);
    assert_eq!(refused(&with(vec![7; 15]), &unlock), Failure::Payload);
    // Trailing bytes of every interesting size, after short and full last chunks.
    for last_plain in [PLAIN, &full[..]] {
        let body = chunk(&key, 0, true, last_plain);
        for extra in [
            1,
            15,
            16,
            17,
            64,
            SEALED_CHUNK,
            SEALED_CHUNK + 1,
            2 * SEALED_CHUNK,
        ] {
            let long = [body.clone(), vec![0; extra]].concat();
            assert_eq!(refused(&with(long), &unlock), Failure::Payload, "{extra}");
        }
    }
    // A whole second file after the first.
    let first = seal_to(PLAIN, &[rec(ID_A)]);
    let second = seal_to(PLAIN, &[rec(ID_A)]);
    assert_eq!(
        refused(&[first, second].concat(), &unlock),
        Failure::Payload
    );
}

#[test]
fn check3_sampled_changes_across_a_larger_file() {
    let keys = x_keys();
    let unlock = Unlock::Identities(&keys);
    let plain = demo_bytes(5 * CHUNK + 777);
    let good = seal_to(&plain, &[rec(ID_A)]);
    // A fixed sequence, so a failure can be repeated.
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..600 {
        let at = (next() % good.len() as u64) as usize;
        let bit = next() % 8;
        let mut bad = good.clone();
        bad[at] ^= 1 << bit;
        refused(&bad, &unlock);
        let cut = (next() % good.len() as u64) as usize;
        refused(&good[..cut], &unlock);
    }
}

#[test]
fn fil03_t04_bad_first_middle_last_chunk_no_final_marker_and_append() {
    let keys = x_keys();
    let unlock = Unlock::Identities(&keys);
    let plain = plain_3();
    let (good, payload) = larger(&plain);
    let t = Temp::new();
    let out = t.sub("out");
    let folder = crate::OutputFolder::open(&out).unwrap();
    let mut cases = Vec::new();
    for offset in [10, SEALED_CHUNK + 10, 2 * SEALED_CHUNK + 10] {
        let mut bad = good.clone();
        bad[payload + offset] ^= 1;
        cases.push(bad);
    }
    cases.push(good[..payload + 2 * SEALED_CHUNK].to_vec());
    cases.push([good.clone(), vec![0]].concat());
    for bad in cases {
        watch::take();
        let error = snapshot(&bad)
            .unlock(&unlock)
            .and_then(|u| u.validate(&mut keep))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error, Error::Decrypt);
        assert_eq!(
            error.to_string(),
            "This file could not be decrypted. Check the passphrase or file key and try again."
        );
        assert!(no_output(&watch::take()), "no final output open or write");
        assert!(names_in(&out).is_empty());
    }
    // The valid file goes through the same folder, to its one new file.
    let valid = snapshot(&good)
        .unlock(&unlock)
        .unwrap()
        .validate(&mut keep)
        .unwrap();
    let Validation::Ready(valid) = valid else {
        panic!("X25519 files have no work factor");
    };
    assert_eq!(valid.plain_len(), plain.len() as u64);
    let name: &std::ffi::OsStr = "demo.out".as_ref();
    valid.save_new(&folder, name, &mut keep).unwrap();
    assert_eq!(fs::read(out.join(name)).unwrap(), plain);
}

#[test]
fn fil03_t16_boundary_files_round_trip_in_both_modes() {
    let keys = x_keys();
    let phrase = secret(PASS);
    for size in [0, 1, 65_535, 65_536, 65_537, 131_071, 131_072, 131_073] {
        let plain = demo_bytes(size);
        let x = seal_to(&plain, &[rec(ID_A)]);
        let payload = x.len() - header_end(&x) - 16;
        let chunks = if size == 0 { 1 } else { size.div_ceil(CHUNK) };
        assert_eq!(payload, size + chunks * 16, "chunk count at {size}");
        assert_eq!(
            open(&x, &Unlock::Identities(&keys)).unwrap(),
            plain,
            "{size}"
        );
        let p = seal_pass(&plain, PASS);
        assert_eq!(
            open(&p, &Unlock::Passphrase(&phrase)).unwrap(),
            plain,
            "{size}"
        );
    }
}
