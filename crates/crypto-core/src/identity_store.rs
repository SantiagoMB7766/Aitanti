//! Encrypted persistence for a small set of per-service demo identities.
//!
//! PKCS#8 is serialized *only in memory*, passed to the encrypted vault layer,
//! and never exposed by this public API.  This is NOT a hardware-backed keystore.

use std::{collections::BTreeMap, error::Error, fmt, path::Path};

use aitanti_vault::{VaultError, private_store};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use zeroize::Zeroizing;

use crate::{CryptoError, ServiceKey};

const FORMAT: &[u8; 8] = b"AITIDS01";
const MAX_KEYS: usize = 16;
const MAX_KEY_BYTES: usize = 4096;
const MAX_SERVICE_BYTES: usize = 253;

#[derive(Debug)]
pub enum IdentityStoreError {
    InvalidFormat,
    DuplicateService,
    MissingService,
    Crypto(CryptoError),
    Vault(VaultError),
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFormat => write!(f, "invalid encrypted identity-store payload"),
            Self::DuplicateService => write!(f, "duplicate service identity"),
            Self::MissingService => write!(f, "requested service identity is not enrolled"),
            Self::Crypto(error) => write!(f, "identity cryptography failed: {error}"),
            Self::Vault(error) => write!(f, "encrypted identity storage failed: {error}"),
        }
    }
}

impl Error for IdentityStoreError {}

impl From<CryptoError> for IdentityStoreError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<VaultError> for IdentityStoreError {
    fn from(value: VaultError) -> Self {
        Self::Vault(value)
    }
}

/// Owns a finite set of in-memory P-256 keys. No Debug implementation and
/// no private-key getters. It is consumed at program exit.
pub struct IdentityStore {
    keys: BTreeMap<String, ServiceKey>,
}

impl IdentityStore {
    /// Two independent fixture identities. Never mix these with real accounts.
    pub fn fixture() -> Result<Self, IdentityStoreError> {
        let mut keys = BTreeMap::new();
        for service in ["service-a.local", "service-b.local"] {
            keys.insert(service.to_owned(), ServiceKey::generate(service)?);
        }
        Ok(Self { keys })
    }

    pub fn identity(&self, service: &str) -> Result<&ServiceKey, IdentityStoreError> {
        self.keys
            .get(service)
            .ok_or(IdentityStoreError::MissingService)
    }

    /// Create a new encrypted file, mode 0600 on Unix. No overwrite and no
    /// temporary plaintext files.  Keep your recovery password safe: there is
    /// deliberately no reset flow.
    pub fn create_new(&self, path: &Path, passphrase: &str) -> Result<(), IdentityStoreError> {
        let data = self.encode()?;
        private_store::create_new(path, &data, passphrase)?;
        Ok(())
    }

    /// Restore the *same* service keys after a process restart.
    pub fn unlock(path: &Path, passphrase: &str) -> Result<Self, IdentityStoreError> {
        let data = private_store::read(path, passphrase)?;
        Self::decode(&data)
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, IdentityStoreError> {
        if self.keys.is_empty() || self.keys.len() > MAX_KEYS {
            return Err(IdentityStoreError::InvalidFormat);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(FORMAT);
        bytes.push(self.keys.len() as u8);
        for (service, identity) in &self.keys {
            if service.is_empty() || service.len() > MAX_SERVICE_BYTES {
                return Err(IdentityStoreError::InvalidFormat);
            }
            let der = identity
                .key_pair
                .to_pkcs8v1()
                .map_err(|_| CryptoError::SigningFailed)?;
            let serialized = der.as_ref();
            if serialized.is_empty() || serialized.len() > MAX_KEY_BYTES {
                return Err(IdentityStoreError::InvalidFormat);
            }
            bytes.extend_from_slice(&(service.len() as u16).to_be_bytes());
            bytes.extend_from_slice(service.as_bytes());
            bytes.extend_from_slice(&(serialized.len() as u16).to_be_bytes());
            bytes.extend_from_slice(serialized);
        }
        Ok(bytes)
    }

    fn decode(data: &[u8]) -> Result<Self, IdentityStoreError> {
        let mut offset = 0;
        if read(data, &mut offset, FORMAT.len())? != &FORMAT[..] {
            return Err(IdentityStoreError::InvalidFormat);
        }
        let count = read(data, &mut offset, 1)?[0] as usize;
        if count == 0 || count > MAX_KEYS {
            return Err(IdentityStoreError::InvalidFormat);
        }
        let mut keys = BTreeMap::new();
        for _ in 0..count {
            let service_len = read_u16(data, &mut offset)? as usize;
            if service_len == 0 || service_len > MAX_SERVICE_BYTES {
                return Err(IdentityStoreError::InvalidFormat);
            }
            let service = std::str::from_utf8(read(data, &mut offset, service_len)?)
                .map_err(|_| IdentityStoreError::InvalidFormat)?
                .to_owned();
            let der_len = read_u16(data, &mut offset)? as usize;
            if der_len == 0 || der_len > MAX_KEY_BYTES {
                return Err(IdentityStoreError::InvalidFormat);
            }
            let der = read(data, &mut offset, der_len)?;
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
                .map_err(|_| IdentityStoreError::InvalidFormat)?;
            if keys
                .insert(
                    service.clone(),
                    ServiceKey {
                        service,
                        key_pair: pair,
                    },
                )
                .is_some()
            {
                return Err(IdentityStoreError::DuplicateService);
            }
        }
        if offset != data.len() {
            return Err(IdentityStoreError::InvalidFormat);
        }
        Ok(Self { keys })
    }
}

fn read<'a>(
    data: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], IdentityStoreError> {
    let end = (*offset)
        .checked_add(len)
        .ok_or(IdentityStoreError::InvalidFormat)?;
    let part = data
        .get(*offset..end)
        .ok_or(IdentityStoreError::InvalidFormat)?;
    *offset = end;
    Ok(part)
}

fn read_u16(data: &[u8], offset: &mut usize) -> Result<u16, IdentityStoreError> {
    let pair: [u8; 2] = read(data, offset, 2)?
        .try_into()
        .map_err(|_| IdentityStoreError::InvalidFormat)?;
    Ok(u16::from_be_bytes(pair))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitanti_protocol::{AuthRequest, PROTOCOL_VERSION};

    const PASS: &str = "fixture-identity-passphrase-123";

    #[test]
    fn identities_survive_restart_and_stay_separated() {
        let original = IdentityStore::fixture().expect("generate");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fixture.aitk");
        original.create_new(&path, PASS).expect("encrypt");
        let recovered = IdentityStore::unlock(&path, PASS).expect("unlock");
        let a = recovered.identity("service-a.local").expect("A");
        let b = recovered.identity("service-b.local").expect("B");
        assert_eq!(
            a.public_key_sec1(),
            original
                .identity("service-a.local")
                .expect("A")
                .public_key_sec1()
        );
        assert_eq!(
            b.public_key_sec1(),
            original
                .identity("service-b.local")
                .expect("B")
                .public_key_sec1()
        );
        assert_ne!(a.public_key_sec1(), b.public_key_sec1());
        let auth =
            AuthRequest::new(PROTOCOL_VERSION, "service-a.local".into(), [7; 32]).expect("auth");
        let sig = a.sign_auth(&auth).expect("sign");
        crate::verify_auth_signature(&a.public_key_sec1(), &auth, &sig).expect("verify");
        assert!(b.sign_auth(&auth).is_err());
    }

    #[test]
    fn wrong_passphrase_refuses_and_existing_file_is_preserved() {
        let store = IdentityStore::fixture().expect("generate");
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("fixture.aitk");
        store.create_new(&path, PASS).expect("create");
        assert!(store.create_new(&path, PASS).is_err());
        assert!(IdentityStore::unlock(&path, "wrong-passphrase-123456").is_err());
        assert!(IdentityStore::unlock(&path, PASS).is_ok());
    }

    #[test]
    fn malformed_serialization_fails_closed() {
        assert!(IdentityStore::decode(b"junk").is_err());
        let mut extra = IdentityStore::fixture()
            .expect("generate")
            .encode()
            .expect("encode");
        extra.push(0);
        assert!(IdentityStore::decode(&extra).is_err());
    }
}
