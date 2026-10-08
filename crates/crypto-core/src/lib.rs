//! Cryptographic primitives used by Aitanti.
//!
//! This crate deliberately exposes narrow operations instead of raw private
//! key material. Private keys remain inside [`ServiceKey`].

use std::error::Error;
use std::fmt;

use aitanti_protocol::{AUTH_CHALLENGE_LEN, AuthRequest};
use aws_lc_rs::{
    rand::{self, SystemRandom},
    signature::{
        ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
        UnparsedPublicKey,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    EmptyService,
    KeyGenerationFailed,
    RandomGenerationFailed,
    SigningFailed,
    VerificationFailed,
    ServiceMismatch { expected: String, actual: String },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyService => write!(f, "service identifier cannot be empty"),
            Self::KeyGenerationFailed => write!(f, "service key generation failed"),
            Self::RandomGenerationFailed => write!(f, "secure random generation failed"),
            Self::SigningFailed => write!(f, "authentication signing failed"),
            Self::VerificationFailed => write!(f, "authentication signature verification failed"),
            Self::ServiceMismatch { expected, actual } => write!(
                f,
                "service mismatch: key is bound to {expected}, request targets {actual}"
            ),
        }
    }
}

impl Error for CryptoError {}

/// A P-256 signing key bound to exactly one service identity.
///
/// There is intentionally no method which exports the private key.
pub struct ServiceKey {
    service: String,
    key_pair: EcdsaKeyPair,
}

impl ServiceKey {
    pub fn generate(service: impl Into<String>) -> Result<Self, CryptoError> {
        let service = service.into();
        if service.is_empty() {
            return Err(CryptoError::EmptyService);
        }

        let key_pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        Ok(Self { service, key_pair })
    }

    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns the public key in uncompressed SEC1 format.
    #[must_use]
    pub fn public_key_sec1(&self) -> Vec<u8> {
        self.key_pair.public_key().as_ref().to_vec()
    }

    /// Signs an Aitanti authentication request only when it targets the
    /// service to which this key is bound.
    pub fn sign_auth(&self, request: &AuthRequest) -> Result<Vec<u8>, CryptoError> {
        if request.service() != self.service {
            return Err(CryptoError::ServiceMismatch {
                expected: self.service.clone(),
                actual: request.service().to_owned(),
            });
        }

        let rng = SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, &request.signing_bytes())
            .map_err(|_| CryptoError::SigningFailed)?;

        Ok(signature.as_ref().to_vec())
    }
}

/// Verifies a fixed-width P-256/SHA-256 ECDSA signature over the canonical
/// authentication message.
pub fn verify_auth_signature(
    public_key_sec1: &[u8],
    request: &AuthRequest,
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_sec1);
    public_key
        .verify(&request.signing_bytes(), signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// Generates a cryptographically random 256-bit challenge.
pub fn generate_challenge() -> Result<[u8; AUTH_CHALLENGE_LEN], CryptoError> {
    let mut challenge = [0u8; AUTH_CHALLENGE_LEN];
    rand::fill(&mut challenge).map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(challenge)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitanti_protocol::PROTOCOL_VERSION;

    fn request(service: &str, challenge: [u8; 32]) -> AuthRequest {
        AuthRequest::new(PROTOCOL_VERSION, service.to_owned(), challenge)
            .expect("test request should be valid")
    }

    #[test]
    fn two_services_get_distinct_public_identities() {
        let a = ServiceKey::generate("service-a.local").expect("key A");
        let b = ServiceKey::generate("service-b.local").expect("key B");

        assert_ne!(a.public_key_sec1(), b.public_key_sec1());
    }

    #[test]
    fn valid_signature_verifies() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let request = request("service-a.local", [7u8; 32]);
        let signature = key.sign_auth(&request).expect("signature");

        verify_auth_signature(&key.public_key_sec1(), &request, &signature)
            .expect("signature should verify");
    }

    #[test]
    fn service_key_refuses_to_sign_for_another_service() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let request = request("service-b.local", [7u8; 32]);

        assert_eq!(
            key.sign_auth(&request),
            Err(CryptoError::ServiceMismatch {
                expected: "service-a.local".to_owned(),
                actual: "service-b.local".to_owned(),
            })
        );
    }

    #[test]
    fn service_binding_is_cryptographically_verified() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let request_a = request("service-a.local", [9u8; 32]);
        let signature = key.sign_auth(&request_a).expect("signature");

        let request_b = request("service-b.local", [9u8; 32]);

        assert_eq!(
            verify_auth_signature(&key.public_key_sec1(), &request_b, &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn different_challenge_invalidates_signature() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let request_a = request("service-a.local", [1u8; 32]);
        let signature = key.sign_auth(&request_a).expect("signature");
        let request_b = request("service-a.local", [2u8; 32]);

        assert_eq!(
            verify_auth_signature(&key.public_key_sec1(), &request_b, &signature),
            Err(CryptoError::VerificationFailed)
        );
    }

    #[test]
    fn generated_challenges_are_not_identical() {
        let a = generate_challenge().expect("challenge A");
        let b = generate_challenge().expect("challenge B");

        assert_ne!(a, b);
    }
}

impl ServiceKey {
    /// Proofs for session operations have their own signing domain. The
    /// service binding is enforced before the signature is created.
    pub fn sign_session(
        &self,
        request: &aitanti_protocol::SessionProofRequest,
    ) -> Result<Vec<u8>, CryptoError> {
        if request.service() != self.service {
            return Err(CryptoError::ServiceMismatch {
                expected: self.service.clone(),
                actual: request.service().to_owned(),
            });
        }
        let rng = SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, &request.signing_bytes())
            .map_err(|_| CryptoError::SigningFailed)?;
        Ok(signature.as_ref().to_vec())
    }
}

pub fn verify_session_signature(
    public_key_sec1: &[u8],
    request: &aitanti_protocol::SessionProofRequest,
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key_sec1);
    public_key
        .verify(&request.signing_bytes(), signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use aitanti_protocol::{PROTOCOL_VERSION, SessionProofRequest};

    #[test]
    fn session_signature_has_distinct_domain_from_authentication() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let auth =
            AuthRequest::new(PROTOCOL_VERSION, "service-a.local".into(), [3; 32]).expect("auth");
        let session = SessionProofRequest::new(
            PROTOCOL_VERSION,
            "service-a.local".into(),
            [1; 32],
            "transfer".into(),
            [3; 32],
        )
        .expect("session");
        let auth_sig = key.sign_auth(&auth).expect("auth sig");
        let session_sig = key.sign_session(&session).expect("session sig");
        assert_eq!(
            verify_session_signature(&key.public_key_sec1(), &session, &auth_sig),
            Err(CryptoError::VerificationFailed)
        );
        verify_session_signature(&key.public_key_sec1(), &session, &session_sig)
            .expect("valid session proof");
    }
}
