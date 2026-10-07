//! In-memory relying-party server used by the Aitanti MVP.
//!
//! The server stores public keys and one-time challenges only. It never
//! receives or stores client private keys.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use aitanti_crypto_core::{CryptoError, generate_challenge, verify_auth_signature};
use aitanti_protocol::{AuthRequest, PROTOCOL_VERSION, ProtocolError};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingChallenge {
    service: String,
    challenge: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerError {
    EmptyService,
    EmptyPublicKey,
    ServiceAlreadyRegistered,
    UnregisteredService,
    UnsupportedProtocolVersion { received: u16 },
    ChallengeUnknownOrConsumed,
    ChallengeGenerationFailed,
    Protocol(ProtocolError),
    Crypto(CryptoError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyService => write!(f, "service identifier cannot be empty"),
            Self::EmptyPublicKey => write!(f, "public key cannot be empty"),
            Self::ServiceAlreadyRegistered => write!(f, "service is already registered"),
            Self::UnregisteredService => write!(f, "service is not registered"),
            Self::UnsupportedProtocolVersion { received } => {
                write!(f, "unsupported protocol version: {received}")
            }
            Self::ChallengeUnknownOrConsumed => {
                write!(f, "challenge is unknown or already consumed")
            }
            Self::ChallengeGenerationFailed => write!(f, "challenge generation failed"),
            Self::Protocol(err) => write!(f, "protocol error: {err}"),
            Self::Crypto(err) => write!(f, "cryptographic error: {err}"),
        }
    }
}

impl Error for ServerError {}

impl From<ProtocolError> for ServerError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<CryptoError> for ServerError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Default)]
pub struct MockServer {
    public_keys: HashMap<String, Vec<u8>>,
    pending_challenges: HashSet<PendingChallenge>,
}

impl MockServer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the public key for a service identity.
    ///
    /// Silent replacement is deliberately forbidden. Key rotation will be a
    /// separate, explicit operation later.
    pub fn register_service(
        &mut self,
        service: impl Into<String>,
        public_key_sec1: Vec<u8>,
    ) -> Result<(), ServerError> {
        let service = service.into();

        if service.is_empty() {
            return Err(ServerError::EmptyService);
        }
        if public_key_sec1.is_empty() {
            return Err(ServerError::EmptyPublicKey);
        }
        if self.public_keys.contains_key(&service) {
            return Err(ServerError::ServiceAlreadyRegistered);
        }

        self.public_keys.insert(service, public_key_sec1);
        Ok(())
    }

    /// Issues a fresh challenge bound to one registered service.
    pub fn issue_challenge(&mut self, service: &str) -> Result<AuthRequest, ServerError> {
        if !self.public_keys.contains_key(service) {
            return Err(ServerError::UnregisteredService);
        }

        // A collision is astronomically unlikely, but we still avoid silently
        // reusing an outstanding challenge.
        for _ in 0..3 {
            let challenge =
                generate_challenge().map_err(|_| ServerError::ChallengeGenerationFailed)?;
            let pending = PendingChallenge {
                service: service.to_owned(),
                challenge,
            };

            if self.pending_challenges.insert(pending) {
                return AuthRequest::new(PROTOCOL_VERSION, service.to_owned(), challenge)
                    .map_err(ServerError::from);
            }
        }

        Err(ServerError::ChallengeGenerationFailed)
    }

    /// Verifies proof-of-possession and consumes the challenge only after a
    /// successful signature verification.
    pub fn verify_auth(
        &mut self,
        request: &AuthRequest,
        signature: &[u8],
    ) -> Result<(), ServerError> {
        if request.version() != PROTOCOL_VERSION {
            return Err(ServerError::UnsupportedProtocolVersion {
                received: request.version(),
            });
        }

        let public_key = self
            .public_keys
            .get(request.service())
            .ok_or(ServerError::UnregisteredService)?;

        let pending = PendingChallenge {
            service: request.service().to_owned(),
            challenge: request.challenge(),
        };

        if !self.pending_challenges.contains(&pending) {
            return Err(ServerError::ChallengeUnknownOrConsumed);
        }

        verify_auth_signature(public_key, request, signature)?;

        // Consume only after successful verification so an attacker cannot
        // invalidate a legitimate challenge merely by sending garbage first.
        self.pending_challenges.remove(&pending);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitanti_crypto_core::ServiceKey;

    fn registered_server(service: &str, key: &ServiceKey) -> MockServer {
        let mut server = MockServer::new();
        server
            .register_service(service, key.public_key_sec1())
            .expect("registration should succeed");
        server
    }

    #[test]
    fn valid_authentication_succeeds_once() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let mut server = registered_server("service-a.local", &key);
        let request = server
            .issue_challenge("service-a.local")
            .expect("challenge");
        let signature = key.sign_auth(&request).expect("signature");

        server
            .verify_auth(&request, &signature)
            .expect("first authentication should succeed");

        assert_eq!(
            server.verify_auth(&request, &signature),
            Err(ServerError::ChallengeUnknownOrConsumed)
        );
    }

    #[test]
    fn invalid_signature_does_not_consume_challenge() {
        let legitimate = ServiceKey::generate("service-a.local").expect("legitimate key");
        let attacker = ServiceKey::generate("service-a.local").expect("attacker key");
        let mut server = registered_server("service-a.local", &legitimate);
        let request = server
            .issue_challenge("service-a.local")
            .expect("challenge");

        let attacker_signature = attacker.sign_auth(&request).expect("attacker signature");
        assert!(matches!(
            server.verify_auth(&request, &attacker_signature),
            Err(ServerError::Crypto(CryptoError::VerificationFailed))
        ));

        let legitimate_signature = legitimate
            .sign_auth(&request)
            .expect("legitimate signature");
        server
            .verify_auth(&request, &legitimate_signature)
            .expect("challenge should still be usable by legitimate key");
    }

    #[test]
    fn unregistered_service_cannot_request_challenge() {
        let mut server = MockServer::new();

        assert_eq!(
            server.issue_challenge("service-a.local"),
            Err(ServerError::UnregisteredService)
        );
    }

    #[test]
    fn registration_cannot_silently_replace_a_key() {
        let first = ServiceKey::generate("service-a.local").expect("first key");
        let second = ServiceKey::generate("service-a.local").expect("second key");
        let mut server = registered_server("service-a.local", &first);

        assert_eq!(
            server.register_service("service-a.local", second.public_key_sec1()),
            Err(ServerError::ServiceAlreadyRegistered)
        );
    }
}
