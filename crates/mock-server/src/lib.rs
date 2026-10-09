//! In-memory relying-party server used by the Aitanti MVP.
//!
//! The server stores public keys, one-time challenges and demo session tokens
//! in memory only. It never receives or stores client private keys.

pub mod http;

use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::time::{Duration, Instant};

use aitanti_crypto_core::{
    CryptoError, generate_challenge, verify_auth_signature, verify_session_signature,
};
use aitanti_protocol::{AuthRequest, PROTOCOL_VERSION, ProtocolError, SessionProofRequest};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PendingChallenge {
    service: String,
    challenge: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerError {
    EmptyService,
    EmptyPublicKey,
    InvalidPublicKey,
    ServiceAlreadyRegistered,
    UnregisteredService,
    UnsupportedProtocolVersion { received: u16 },
    ChallengeUnknownOrConsumed,
    ChallengeGenerationFailed,
    UnknownSession,
    SessionServiceMismatch,
    SessionChallengeUnknownOrConsumed,
    CapacityExceeded,
    Protocol(ProtocolError),
    Crypto(CryptoError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyService => write!(f, "service identifier cannot be empty"),
            Self::EmptyPublicKey => write!(f, "public key cannot be empty"),
            Self::InvalidPublicKey => write!(f, "unsupported public key encoding"),
            Self::ServiceAlreadyRegistered => write!(f, "service is already registered"),
            Self::UnregisteredService => write!(f, "service is not registered"),
            Self::UnsupportedProtocolVersion { received } => {
                write!(f, "unsupported protocol version: {received}")
            }
            Self::ChallengeUnknownOrConsumed => {
                write!(f, "challenge is unknown or already consumed")
            }
            Self::ChallengeGenerationFailed => write!(f, "challenge generation failed"),
            Self::UnknownSession => write!(f, "unknown session"),
            Self::SessionServiceMismatch => write!(f, "session service does not match proof"),
            Self::SessionChallengeUnknownOrConsumed => {
                write!(f, "session challenge unknown or already consumed")
            }
            Self::CapacityExceeded => write!(f, "server demo resource limit reached"),
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

/// Limits for the in-memory demo only. No state survives a server restart.
#[derive(Debug, Clone)]
pub struct ServerLimits {
    pub challenge_ttl: Duration,
    pub session_ttl: Duration,
    pub max_services: usize,
    pub max_pending_auth: usize,
    pub max_pending_proofs: usize,
    pub max_sessions: usize,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            challenge_ttl: Duration::from_secs(60),
            session_ttl: Duration::from_secs(600),
            max_services: 32,
            max_pending_auth: 256,
            max_pending_proofs: 256,
            max_sessions: 128,
        }
    }
}

struct SessionRecord {
    service: String,
    expires_at: Instant,
}

pub struct MockServer {
    public_keys: HashMap<String, Vec<u8>>,
    pending_challenges: HashMap<PendingChallenge, Instant>,
    sessions: HashMap<[u8; 32], SessionRecord>,
    pending_session_proofs: HashMap<SessionChallenge, Instant>,
    limits: ServerLimits,
}

impl Default for MockServer {
    fn default() -> Self {
        Self::with_limits(ServerLimits::default())
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct SessionChallenge {
    token: [u8; 32],
    action: String,
    challenge: [u8; 32],
}

impl MockServer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_limits(limits: ServerLimits) -> Self {
        Self {
            public_keys: HashMap::new(),
            pending_challenges: HashMap::new(),
            sessions: HashMap::new(),
            pending_session_proofs: HashMap::new(),
            limits,
        }
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        self.pending_challenges
            .retain(|_, expires_at| *expires_at > now);
        self.sessions.retain(|_, record| record.expires_at > now);
        self.pending_session_proofs
            .retain(|key, expires_at| *expires_at > now && self.sessions.contains_key(&key.token));
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
        // Aitanti MVP uses uncompressed P-256 SEC1 only; curve validity is
        // subsequently checked by the verifier during authentication.
        if public_key_sec1.len() != 65 || public_key_sec1[0] != 0x04 {
            return Err(ServerError::InvalidPublicKey);
        }
        if self.public_keys.contains_key(&service) {
            return Err(ServerError::ServiceAlreadyRegistered);
        }

        if self.public_keys.len() >= self.limits.max_services {
            return Err(ServerError::CapacityExceeded);
        }
        self.public_keys.insert(service, public_key_sec1);
        Ok(())
    }

    /// Issues a fresh challenge bound to one registered service.
    pub fn issue_challenge(&mut self, service: &str) -> Result<AuthRequest, ServerError> {
        self.prune_expired();
        if !self.public_keys.contains_key(service) {
            return Err(ServerError::UnregisteredService);
        }
        if self.pending_challenges.len() >= self.limits.max_pending_auth {
            return Err(ServerError::CapacityExceeded);
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

            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.pending_challenges.entry(pending)
            {
                entry.insert(Instant::now() + self.limits.challenge_ttl);
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
        self.prune_expired();
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

        if !self.pending_challenges.contains_key(&pending) {
            return Err(ServerError::ChallengeUnknownOrConsumed);
        }

        verify_auth_signature(public_key, request, signature)?;

        // Consume only after successful verification so an attacker cannot
        // invalidate a legitimate challenge merely by sending garbage first.
        self.pending_challenges.remove(&pending);
        Ok(())
    }
}

impl MockServer {
    /// Authenticates a registered per-service key before minting a 256-bit
    /// bearer token. Possession of that token ALONE does not authorize any
    /// sensitive operation in this demo.
    pub fn login(
        &mut self,
        request: &AuthRequest,
        signature: &[u8],
    ) -> Result<[u8; 32], ServerError> {
        self.prune_expired();
        if self.sessions.len() >= self.limits.max_sessions {
            return Err(ServerError::CapacityExceeded);
        }
        self.verify_auth(request, signature)?;
        for _ in 0..3 {
            let token = generate_challenge().map_err(|_| ServerError::ChallengeGenerationFailed)?;
            if let std::collections::hash_map::Entry::Vacant(entry) = self.sessions.entry(token) {
                entry.insert(SessionRecord {
                    service: request.service().to_owned(),
                    expires_at: Instant::now() + self.limits.session_ttl,
                });
                return Ok(token);
            }
        }
        Err(ServerError::ChallengeGenerationFailed)
    }

    /// Ends a demo session and invalidates all unused operation challenges.
    /// A revoked session token cannot authorize an action, even with a signature.
    pub fn revoke_session(&mut self, token: [u8; 32]) -> Result<(), ServerError> {
        self.prune_expired();
        self.sessions
            .remove(&token)
            .ok_or(ServerError::UnknownSession)?;
        self.pending_session_proofs
            .retain(|challenge, _| challenge.token != token);
        Ok(())
    }

    /// Issues a one-time challenge for one exact session and action.
    pub fn issue_session_challenge(
        &mut self,
        token: [u8; 32],
        action: &str,
    ) -> Result<SessionProofRequest, ServerError> {
        self.prune_expired();
        let service = self
            .sessions
            .get(&token)
            .ok_or(ServerError::UnknownSession)?
            .service
            .clone();
        if self.pending_session_proofs.len() >= self.limits.max_pending_proofs {
            return Err(ServerError::CapacityExceeded);
        }
        for _ in 0..3 {
            let challenge =
                generate_challenge().map_err(|_| ServerError::ChallengeGenerationFailed)?;
            let request = SessionProofRequest::new(
                PROTOCOL_VERSION,
                service.clone(),
                token,
                action.to_owned(),
                challenge,
            )?;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                self.pending_session_proofs.entry(SessionChallenge {
                    token,
                    action: action.to_owned(),
                    challenge,
                })
            {
                entry.insert(Instant::now() + self.limits.challenge_ttl);
                return Ok(request);
            }
        }
        Err(ServerError::ChallengeGenerationFailed)
    }

    /// Verifies token + signed action proof + fresh challenge + registered
    /// public key. A failed proof cannot burn the legitimate nonce.
    pub fn execute_sensitive(
        &mut self,
        request: &SessionProofRequest,
        signature: &[u8],
    ) -> Result<(), ServerError> {
        self.prune_expired();
        if request.version() != PROTOCOL_VERSION {
            return Err(ServerError::UnsupportedProtocolVersion {
                received: request.version(),
            });
        }
        let registered_service = self
            .sessions
            .get(&request.token())
            .ok_or(ServerError::UnknownSession)?;
        if registered_service.service != request.service() {
            return Err(ServerError::SessionServiceMismatch);
        }
        let pending = SessionChallenge {
            token: request.token(),
            action: request.action().to_owned(),
            challenge: request.challenge(),
        };
        if !self.pending_session_proofs.contains_key(&pending) {
            return Err(ServerError::SessionChallengeUnknownOrConsumed);
        }
        let public_key = self
            .public_keys
            .get(request.service())
            .ok_or(ServerError::UnregisteredService)?;
        verify_session_signature(public_key, request, signature)?;
        self.pending_session_proofs.remove(&pending);
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

#[cfg(test)]
mod session_tests {
    use super::*;
    use aitanti_crypto_core::ServiceKey;

    fn logged_in() -> (ServiceKey, MockServer, [u8; 32]) {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let mut server = MockServer::new();
        server
            .register_service("service-a.local", key.public_key_sec1())
            .expect("register");
        let auth = server
            .issue_challenge("service-a.local")
            .expect("auth challenge");
        let signature = key.sign_auth(&auth).expect("sign auth");
        let token = server.login(&auth, &signature).expect("login");
        (key, server, token)
    }

    #[test]
    fn stolen_token_alone_cannot_authorize_action() {
        let (_key, mut server, token) = logged_in();
        let proof = server
            .issue_session_challenge(token, "transfer")
            .expect("proof challenge");
        assert!(matches!(
            server.execute_sensitive(&proof, &[]),
            Err(ServerError::Crypto(CryptoError::VerificationFailed))
        ));
    }

    #[test]
    fn signed_proof_is_one_time_and_action_bound() {
        let (key, mut server, token) = logged_in();
        let proof = server
            .issue_session_challenge(token, "transfer")
            .expect("challenge");
        let sig = key.sign_session(&proof).expect("sign");
        server.execute_sensitive(&proof, &sig).expect("valid proof");
        assert!(matches!(
            server.execute_sensitive(&proof, &sig),
            Err(ServerError::SessionChallengeUnknownOrConsumed)
        ));
        let second = server
            .issue_session_challenge(token, "read")
            .expect("challenge 2");
        assert!(matches!(
            server.execute_sensitive(&second, &sig),
            Err(ServerError::Crypto(CryptoError::VerificationFailed))
        ));
    }

    #[test]
    fn attacker_private_key_cannot_authorize_action() {
        let (key, mut server, token) = logged_in();
        let attacker = ServiceKey::generate("service-a.local").expect("other key");
        let proof = server
            .issue_session_challenge(token, "transfer")
            .expect("challenge");
        let bad_sig = attacker.sign_session(&proof).expect("bad sign");
        assert!(matches!(
            server.execute_sensitive(&proof, &bad_sig),
            Err(ServerError::Crypto(CryptoError::VerificationFailed))
        ));
        server
            .execute_sensitive(&proof, &key.sign_session(&proof).expect("good sign"))
            .expect("challenge still valid");
    }

    #[test]
    fn unauthorized_token_is_not_a_session() {
        let (_key, mut server, _token) = logged_in();
        assert!(matches!(
            server.issue_session_challenge([0u8; 32], "transfer"),
            Err(ServerError::UnknownSession)
        ));
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use aitanti_crypto_core::ServiceKey;

    #[test]
    fn revoked_session_rejects_signed_pending_action() {
        let key = ServiceKey::generate("service-a.local").expect("generate key");
        let mut server = MockServer::new();
        server
            .register_service("service-a.local", key.public_key_sec1())
            .expect("register");
        let auth = server
            .issue_challenge("service-a.local")
            .expect("challenge");
        let auth_sig = key.sign_auth(&auth).expect("sign auth");
        let token = server.login(&auth, &auth_sig).expect("login");
        let request = server
            .issue_session_challenge(token, "transfer")
            .expect("challenge");
        let signature = key.sign_session(&request).expect("sign operation");
        server.revoke_session(token).expect("revoke");
        assert_eq!(
            server.execute_sensitive(&request, &signature),
            Err(ServerError::UnknownSession)
        );
        assert_eq!(
            server.revoke_session(token),
            Err(ServerError::UnknownSession)
        );
        assert_eq!(
            server.issue_session_challenge(token, "transfer"),
            Err(ServerError::UnknownSession)
        );
    }
}

#[cfg(test)]
mod expiration_and_limit_tests {
    use super::*;
    use aitanti_crypto_core::ServiceKey;

    #[test]
    fn expired_authentication_challenge_is_rejected() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let mut server = MockServer::with_limits(ServerLimits {
            challenge_ttl: Duration::ZERO,
            ..ServerLimits::default()
        });
        server
            .register_service("service-a.local", key.public_key_sec1())
            .expect("register");
        let challenge = server.issue_challenge("service-a.local").expect("issue");
        let signature = key.sign_auth(&challenge).expect("sign");
        assert_eq!(
            server.verify_auth(&challenge, &signature),
            Err(ServerError::ChallengeUnknownOrConsumed)
        );
    }

    #[test]
    fn zero_ttl_session_cannot_authorize_sensitive_action() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let mut server = MockServer::with_limits(ServerLimits {
            session_ttl: Duration::ZERO,
            ..ServerLimits::default()
        });
        server
            .register_service("service-a.local", key.public_key_sec1())
            .expect("register");
        let challenge = server.issue_challenge("service-a.local").expect("issue");
        let token = server
            .login(&challenge, &key.sign_auth(&challenge).expect("sign"))
            .expect("login");
        assert_eq!(
            server.issue_session_challenge(token, "sensitive-demo-action"),
            Err(ServerError::UnknownSession)
        );
    }

    #[test]
    fn pending_authentication_challenges_have_hard_limit() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let mut server = MockServer::with_limits(ServerLimits {
            max_pending_auth: 1,
            ..ServerLimits::default()
        });
        server
            .register_service("service-a.local", key.public_key_sec1())
            .expect("register");
        let first = server.issue_challenge("service-a.local").expect("issue");
        assert_eq!(
            server.issue_challenge("service-a.local"),
            Err(ServerError::CapacityExceeded)
        );
        server
            .verify_auth(&first, &key.sign_auth(&first).expect("sign"))
            .expect("verify");
        server
            .issue_challenge("service-a.local")
            .expect("capacity recycled");
    }

    #[test]
    fn registration_is_bounded_and_rejects_non_sec1_keys() {
        let key_a = ServiceKey::generate("service-a.local").expect("key a");
        let key_b = ServiceKey::generate("service-b.local").expect("key b");
        let mut server = MockServer::with_limits(ServerLimits {
            max_services: 1,
            ..ServerLimits::default()
        });
        assert_eq!(
            server.register_service("bad.local", vec![3; 32]),
            Err(ServerError::InvalidPublicKey)
        );
        server
            .register_service("service-a.local", key_a.public_key_sec1())
            .expect("first registration");
        assert_eq!(
            server.register_service("service-b.local", key_b.public_key_sec1()),
            Err(ServerError::CapacityExceeded)
        );
    }

    #[test]
    fn expired_pending_proof_does_not_authorize_action() {
        let key = ServiceKey::generate("service-a.local").expect("key");
        let mut server = MockServer::new();
        server
            .register_service("service-a.local", key.public_key_sec1())
            .expect("register");
        let auth = server
            .issue_challenge("service-a.local")
            .expect("challenge");
        let token = server
            .login(&auth, &key.sign_auth(&auth).expect("sign"))
            .expect("login");
        let proof = server
            .issue_session_challenge(token, "sensitive-demo-action")
            .expect("proof");
        // Drive the timeout to zero after issuing the challenge, without sleeping.
        server.limits.challenge_ttl = Duration::ZERO;
        server.pending_session_proofs.insert(
            SessionChallenge {
                token,
                action: proof.action().to_owned(),
                challenge: proof.challenge(),
            },
            Instant::now(),
        );
        assert_eq!(
            server.execute_sensitive(&proof, &key.sign_session(&proof).expect("sign")),
            Err(ServerError::SessionChallengeUnknownOrConsumed)
        );
    }
}
