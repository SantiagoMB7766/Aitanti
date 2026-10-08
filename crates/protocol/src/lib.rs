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
    EmptyAction,
    ActionTooLong { len: usize },
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyService => write!(f, "service identifier cannot be empty"),
            Self::ServiceTooLong { len } => {
                write!(f, "service identifier is too long: {len} bytes")
            }
            Self::EmptyAction => write!(f, "action cannot be empty"),
            Self::ActionTooLong { len } => write!(f, "action too long: {len} bytes"),
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

/// A separate domain for signing a sensitive session operation. An auth
/// signature can never be accepted as a session proof.
pub const SESSION_DOMAIN: &[u8] = b"aitanti/session-proof";

/// Canonical request binding a particular session token, service, action,
/// version and one-time challenge to the device's signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProofRequest {
    version: u16,
    service: String,
    token: [u8; 32],
    action: String,
    challenge: [u8; 32],
}

impl SessionProofRequest {
    pub fn new(
        version: u16,
        service: String,
        token: [u8; 32],
        action: String,
        challenge: [u8; 32],
    ) -> Result<Self, ProtocolError> {
        if service.is_empty() {
            return Err(ProtocolError::EmptyService);
        }
        if service.len() > usize::from(u16::MAX) {
            return Err(ProtocolError::ServiceTooLong { len: service.len() });
        }
        if action.is_empty() {
            return Err(ProtocolError::EmptyAction);
        }
        if action.len() > usize::from(u16::MAX) {
            return Err(ProtocolError::ActionTooLong { len: action.len() });
        }
        Ok(Self {
            version,
            service,
            token,
            action,
            challenge,
        })
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    #[must_use]
    pub fn version(&self) -> u16 {
        self.version
    }

    #[must_use]
    pub fn token(&self) -> [u8; 32] {
        self.token
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub fn challenge(&self) -> [u8; 32] {
        self.challenge
    }

    /// Explicit field lengths and network byte order, independently versioned
    /// by protocol version. Avoid ad-hoc JSON or ambiguous string concatenation.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(
            SESSION_DOMAIN.len() + 2 + 2 + self.service.len() + 32 + 2 + self.action.len() + 32,
        );
        output.extend_from_slice(SESSION_DOMAIN);
        output.extend_from_slice(&self.version.to_be_bytes());
        output.extend_from_slice(&(self.service.len() as u16).to_be_bytes());
        output.extend_from_slice(self.service.as_bytes());
        output.extend_from_slice(&self.token);
        output.extend_from_slice(&(self.action.len() as u16).to_be_bytes());
        output.extend_from_slice(self.action.as_bytes());
        output.extend_from_slice(&self.challenge);
        output
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn proof(action: &str) -> SessionProofRequest {
        SessionProofRequest::new(
            PROTOCOL_VERSION,
            "service-a.local".into(),
            [1; 32],
            action.into(),
            [2; 32],
        )
        .expect("valid fixture")
    }

    #[test]
    fn action_is_cryptographically_bound() {
        assert_ne!(
            proof("read").signing_bytes(),
            proof("transfer").signing_bytes()
        );
    }

    #[test]
    fn auth_and_session_domains_differ() {
        assert_ne!(AUTH_DOMAIN, SESSION_DOMAIN);
    }

    #[test]
    fn empty_action_is_rejected() {
        assert_eq!(
            SessionProofRequest::new(1, "a".into(), [0; 32], String::new(), [0; 32]),
            Err(ProtocolError::EmptyAction),
        );
    }
}
