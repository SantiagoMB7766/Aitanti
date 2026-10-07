//! Public protocol types for Aitanti.
//!
//! This crate defines protocol messages and their canonical byte
//! representation. Cryptographic operations do not belong here.

use std::error::Error;
use std::fmt;

pub const PROTOCOL_VERSION: u16 = 1;
pub const AUTH_DOMAIN: &[u8] = b"aitanti/auth";
pub const AUTH_CHALLENGE_LEN: usize = 32;

/// Authentication request issued for one Aitanti service.
///
/// Instances can only be created through [`AuthRequest::new`] so that
/// invalid service identifiers are rejected before anything is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    version: u16,
    service: String,
    challenge: [u8; AUTH_CHALLENGE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    EmptyService,
    ServiceTooLong { len: usize },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyService => write!(f, "service identifier cannot be empty"),
            Self::ServiceTooLong { len } => {
                write!(f, "service identifier is too long: {len} bytes")
            }
        }
    }
}

impl Error for ProtocolError {}

impl AuthRequest {
    pub fn new(
        version: u16,
        service: String,
        challenge: [u8; AUTH_CHALLENGE_LEN],
    ) -> Result<Self, ProtocolError> {
        if service.is_empty() {
            return Err(ProtocolError::EmptyService);
        }

        if service.len() > usize::from(u16::MAX) {
            return Err(ProtocolError::ServiceTooLong { len: service.len() });
        }

        Ok(Self {
            version,
            service,
            challenge,
        })
    }

    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    #[must_use]
    pub fn challenge(&self) -> [u8; AUTH_CHALLENGE_LEN] {
        self.challenge
    }

    /// Returns the canonical bytes that are signed for authentication.
    ///
    /// Layout:
    ///
    /// ```text
    /// AUTH_DOMAIN
    /// version      : u16 big-endian
    /// service_len  : u16 big-endian
    /// service      : UTF-8 bytes
    /// challenge    : 32 bytes
    /// ```
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Safe because `new` rejects services that do not fit in u16.
        let service_len = self.service.len() as u16;

        let mut bytes = Vec::with_capacity(
            AUTH_DOMAIN.len()
                + std::mem::size_of::<u16>()
                + std::mem::size_of::<u16>()
                + self.service.len()
                + AUTH_CHALLENGE_LEN,
        );

        bytes.extend_from_slice(AUTH_DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        bytes.extend_from_slice(&service_len.to_be_bytes());
        bytes.extend_from_slice(self.service.as_bytes());
        bytes.extend_from_slice(&self.challenge);

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(service: &str, challenge: [u8; 32]) -> AuthRequest {
        AuthRequest::new(PROTOCOL_VERSION, service.to_owned(), challenge)
            .expect("test request should be valid")
    }

    #[test]
    fn same_request_produces_same_signing_bytes() {
        let a = request("service-a.local", [1u8; 32]);
        let b = request("service-a.local", [1u8; 32]);

        assert_eq!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn different_service_produces_different_signing_bytes() {
        let a = request("service-a.local", [1u8; 32]);
        let b = request("service-b.local", [1u8; 32]);

        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn different_challenge_produces_different_signing_bytes() {
        let a = request("service-a.local", [1u8; 32]);
        let b = request("service-a.local", [2u8; 32]);

        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn different_version_produces_different_signing_bytes() {
        let a = AuthRequest::new(1, "service-a.local".to_owned(), [1u8; 32])
            .expect("version 1 request should be valid");

        let b = AuthRequest::new(2, "service-a.local".to_owned(), [1u8; 32])
            .expect("version 2 request should be valid");

        assert_ne!(a.signing_bytes(), b.signing_bytes());
    }

    #[test]
    fn empty_service_is_rejected() {
        let result = AuthRequest::new(PROTOCOL_VERSION, String::new(), [1u8; 32]);

        assert_eq!(result, Err(ProtocolError::EmptyService));
    }

    #[test]
    fn service_too_long_is_rejected() {
        let service = "a".repeat(usize::from(u16::MAX) + 1);

        let result = AuthRequest::new(PROTOCOL_VERSION, service, [1u8; 32]);

        assert_eq!(
            result,
            Err(ProtocolError::ServiceTooLong {
                len: usize::from(u16::MAX) + 1,
            })
        );
    }

    #[test]
    fn canonical_encoding_has_expected_layout() {
        let request = AuthRequest::new(
            PROTOCOL_VERSION,
            "abc".to_owned(),
            [0xAA; AUTH_CHALLENGE_LEN],
        )
        .expect("test request should be valid");

        let bytes = request.signing_bytes();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"aitanti/auth");
        expected.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        expected.extend_from_slice(&3u16.to_be_bytes());
        expected.extend_from_slice(b"abc");
        expected.extend_from_slice(&[0xAA; AUTH_CHALLENGE_LEN]);

        assert_eq!(bytes, expected);
    }
}
