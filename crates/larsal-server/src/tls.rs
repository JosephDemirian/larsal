//! The demo certificate and TLS (SYN-01.1, SYN-01.2; P17, P20).
//!
//! At the first start the server makes a self-signed certificate with rcgen:
//! a P-256 key, subject names `localhost` and `127.0.0.1`. It keeps the
//! certificate and its key in `tls/cert.der` and `tls/key.der` (mode 0600,
//! SYN-02.1) and loads them at every later start, so the fingerprint a user
//! compared stays the same. TLS is rustls on ring, TLS 1.3 and 1.2 only.
//!
//! The key's bytes live in a `SecretBytes` and reach rustls only borrowed;
//! the parsed key that ring and rcgen keep is theirs (the TLS exception of
//! P20). The key is never printed or logged.

use crate::Error;
use crate::data::DataFolder;
use larsal_crypto::secret::SecretBytes;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::rustls::crypto::ring::{default_provider, sign::any_supported_type};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio_rustls::rustls::{ServerConfig, version};

/// The server's certificate and its key.
pub struct Certificate {
    der: CertificateDer<'static>,
    key: SecretBytes,
}

impl std::fmt::Debug for Certificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Certificate")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

impl Certificate {
    /// Loads `tls/cert.der` and `tls/key.der`, or makes and stores them
    /// when neither exists (the first start).
    ///
    /// # Errors
    /// Only one of the two files exists, a file cannot be read or written,
    /// or the key does not belong to the certificate.
    pub fn load_or_make(folder: &DataFolder) -> Result<Self, Error> {
        let dir = folder.tls();
        let (cert_path, key_path) = (dir.join("cert.der"), dir.join("key.der"));
        let cert = match (
            fs::symlink_metadata(&cert_path),
            fs::symlink_metadata(&key_path),
        ) {
            (Ok(_), Ok(_)) => Self {
                der: CertificateDer::from(read(&cert_path)?),
                key: SecretBytes::new(read(&key_path)?),
            },
            (Err(_), Err(_)) => {
                let made = make()?;
                // The key first: a start that stops in between finds no
                // certificate and refuses, never a certificate without its key.
                write_new(&key_path, made.key.expose())?;
                write_new(&cert_path, &made.der)?;
                made
            }
            _ => {
                return Err(Error::new(format!(
                    "{} holds only one of cert.der and key.der; delete both to make a new \
                     certificate (its fingerprint changes, so every Mac must compare it again)",
                    dir.display()
                )));
            }
        };
        cert.certified_key()?;
        Ok(cert)
    }

    /// The certificate's DER bytes, as the server presents them.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The SHA-256 of the certificate's DER bytes as 64 uppercase hex
    /// digits in 8 groups of 8, as the server prints it (SYN-01.2).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let hash = larsal_crypto::hash::sha256(&[self.der.as_ref()]);
        let hex: Vec<String> = hash.expose().iter().map(|b| format!("{b:02X}")).collect();
        hex.chunks(4)
            .map(|group| group.concat())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn certified_key(&self) -> Result<CertifiedKey, Error> {
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key.expose()));
        let key = any_supported_type(&der)
            .map_err(|e| Error::new(format!("tls/key.der is not a usable key: {e}")))?;
        let certified = CertifiedKey::new(vec![self.der.clone()], key);
        certified
            .keys_match()
            .map_err(|_| Error::new("tls/key.der does not belong to tls/cert.der"))?;
        Ok(certified)
    }

    /// The rustls configuration: ring, TLS 1.3 and 1.2 only, HTTP/1.1 by
    /// ALPN, no client certificates (SYN-01.1).
    ///
    /// # Errors
    /// The key does not fit rustls.
    pub fn server_config(&self) -> Result<Arc<ServerConfig>, Error> {
        let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_protocol_versions(&[&version::TLS13, &version::TLS12])
            .map_err(|e| Error::new(format!("cannot set up TLS: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(self.certified_key()?)));
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

fn make() -> Result<Certificate, Error> {
    let failed = |e: rcgen::Error| Error::new(format!("cannot make the certificate: {e}"));
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(failed)?;
    let mut params = CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
        .map_err(failed)?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Larsal sync server (demo)");
    params.distinguished_name = name;
    let cert = params.self_signed(&key).map_err(failed)?;
    Ok(Certificate {
        der: cert.der().clone(),
        key: SecretBytes::new(key.serialize_der()),
    })
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    fs::read(path).map_err(|e| Error::new(format!("cannot read {}: {e}", path.display())))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let failed = |e: std::io::Error| Error::new(format!("cannot write {}: {e}", path.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(failed)?;
    file.write_all(bytes).map_err(failed)?;
    file.sync_all().map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::open;
    use crate::data::tests::{Scratch, block_on};
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn syn01_2_first_start_makes_files_second_loads_them() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let folder = block_on(open(&root)).unwrap();
        let first = Certificate::load_or_make(&folder).unwrap();
        for file in ["cert.der", "key.der"] {
            let meta = fs::metadata(folder.tls().join(file)).unwrap();
            assert_eq!(meta.mode() & 0o7777, 0o600, "{file}");
        }
        assert_eq!(
            fs::read(folder.tls().join("cert.der")).unwrap(),
            first.der()
        );
        drop(folder);
        let again = Certificate::load_or_make(&block_on(open(&root)).unwrap()).unwrap();
        assert_eq!(again.der(), first.der());
        assert_eq!(again.fingerprint(), first.fingerprint());
        again.server_config().unwrap();
    }

    #[test]
    fn syn01_2_fingerprint_is_sha256_of_der_in_8_groups() {
        let cert = make().unwrap();
        let print = cert.fingerprint();
        let groups: Vec<&str> = print.split(' ').collect();
        assert_eq!(groups.len(), 8, "{print}");
        for g in &groups {
            assert_eq!(g.len(), 8);
            assert!(
                g.bytes()
                    .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
            );
        }
        // The same digest written another way.
        let hash = larsal_crypto::hash::sha256(&[cert.der()]);
        let mut want = String::new();
        for b in hash.expose() {
            want.push_str(&format!("{b:02x}"));
        }
        assert_eq!(groups.concat(), want.to_uppercase());
    }

    #[test]
    fn syn01_2_key_and_certificate_are_p256() {
        let cert = make().unwrap();
        // The certificate's key names prime256v1 (1.2.840.10045.3.1.7).
        let p256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        assert!(cert.der().windows(p256.len()).any(|w| w == p256));
        let key = KeyPair::try_from(cert.key.expose()).unwrap();
        assert_eq!(key.algorithm(), &PKCS_ECDSA_P256_SHA256);
    }

    #[test]
    fn syn01_2_one_file_missing_or_wrong_key_refused() {
        let scratch = Scratch::new();
        let root = scratch.0.join("data");
        let folder = block_on(open(&root)).unwrap();
        Certificate::load_or_make(&folder).unwrap();
        let key = folder.tls().join("key.der");
        let saved = fs::read(&key).unwrap();
        fs::remove_file(&key).unwrap();
        let err = Certificate::load_or_make(&folder).unwrap_err().to_string();
        assert!(err.contains("only one of cert.der and key.der"), "{err}");
        // Another key in place of the certificate's own.
        write_new(&key, make().unwrap().key.expose()).unwrap();
        let err = Certificate::load_or_make(&folder).unwrap_err().to_string();
        assert_eq!(err, "tls/key.der does not belong to tls/cert.der");
        fs::remove_file(&key).unwrap();
        write_new(&key, &saved).unwrap();
        Certificate::load_or_make(&folder).unwrap();
    }

    #[test]
    fn syn01_2_debug_shows_no_key() {
        let cert = make().unwrap();
        let text = format!("{cert:?}");
        assert!(text.contains(&cert.fingerprint()));
        let key_hex: String = cert
            .key
            .expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!text.to_lowercase().contains(&key_hex[..16]));
        assert!(!text.contains("key"));
    }
}
