//! F-070 (LD-209 change 3): the private bytes of an SSH key type ssh-key
//! does not know are wiped on drop. A probe allocator looks for a marker
//! from those bytes in every block handed back; no freed memory is read.
//! One test only: the probe counts every block the process frees.

use larsal_crypto::ssh::OpenSshKey;
use larsal_platform::memory::{Probe, Seen, set_needle};
use ssh_key::private::{KeypairData, OpaqueKeypair};
use ssh_key::public::OpaquePublicKey;
use ssh_key::{Algorithm, AlgorithmName, LineEnding, PrivateKey};
use std::alloc::System;
use std::sync::atomic::Ordering::Relaxed;

static SEEN: Seen = Seen::new();

#[global_allocator]
static ALLOC: Probe<System> = Probe(System, &SEEN);

const MARKER: [u8; 8] = *b"F070demo";

#[test]
fn f_070_unknown_type_private_bytes_are_wiped_on_drop() {
    let name = Algorithm::Other(AlgorithmName::new("demo-unknown@example.com").unwrap());
    let pair = OpaqueKeypair::new(
        [MARKER; 4].concat(),
        OpaquePublicKey::new(vec![1; 32], name),
    );
    let pem = PrivateKey::new(KeypairData::Other(pair), "demo")
        .unwrap()
        .to_openssh(LineEnding::LF)
        .unwrap();
    set_needle(MARKER);
    SEEN.reset();
    let key = OpenSshKey::parse(pem.as_bytes()).expect("an unprotected key of an unknown type");
    assert_eq!(key.algorithm(), "demo-unknown@example.com");
    drop(key);
    let (freed, left) = (SEEN.freed.load(Relaxed), SEEN.with_needle.load(Relaxed));
    set_needle([0; 8]);
    assert!(freed > 0);
    assert_eq!(left, 0, "a freed block still held the private bytes");
}
