//! Demo-only HTTP adapter. No production enrolment, TLS, persistence or browser bridge.
//! Binding is restricted to 127.0.0.1 by the binary, and no CORS is enabled.

use std::sync::{Arc, Mutex};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};

use crate::MockServer;
use aitanti_protocol::{AuthRequest, SessionProofRequest};

pub type SharedServer = Arc<Mutex<MockServer>>;
type ApiResult<T> = Result<Json<T>, StatusCode>;

#[derive(Serialize, Deserialize)]
pub struct ServiceRegistration {
    pub service: String,
    pub public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct ServiceQuery {
    pub service: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthWire {
    pub version: u16,
    pub service: String,
    pub challenge: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct SignedAuthWire {
    pub version: u16,
    pub service: String,
    pub challenge: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct TokenWire {
    pub token: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct ActionQuery {
    pub token: [u8; 32],
    pub action: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProofWire {
    pub version: u16,
    pub service: String,
    pub token: [u8; 32],
    pub action: String,
    pub challenge: [u8; 32],
}

#[derive(Serialize, Deserialize)]
pub struct SignedProofWire {
    pub version: u16,
    pub service: String,
    pub token: [u8; 32],
    pub action: String,
    pub challenge: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct OkWire {
    pub ok: bool,
}

async fn local_only(req: Request<axum::body::Body>, next: Next) -> Result<Response, StatusCode> {
    // Reject Host-based DNS rebinding attempts and all browser-originated calls.
    // This is an extra demo control, NOT authentication against local processes.
    let headers = req.headers();
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let is_ipv4_loopback_host = host
        .and_then(|h| h.strip_prefix("127.0.0.1:"))
        .is_some_and(|port| port.parse::<u16>().is_ok_and(|p| p != 0));
    if !is_ipv4_loopback_host
        || headers.contains_key(header::ORIGIN)
        || headers.contains_key("sec-fetch-site")
    {
        return Err(StatusCode::FORBIDDEN);
    }
    if req.uri().path() != "/healthz" {
        if headers.get("x-aitanti-demo-client") != Some(&HeaderValue::from_static("1")) {
            return Err(StatusCode::FORBIDDEN);
        }
        if req.method() == axum::http::Method::POST {
            let media = headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            if !media.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }
    }
    Ok(next.run(req).await)
}

fn lock(state: &SharedServer) -> Result<std::sync::MutexGuard<'_, MockServer>, StatusCode> {
    state.lock().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn health() -> Json<OkWire> {
    Json(OkWire { ok: true })
}

async fn register(
    State(state): State<SharedServer>,
    Json(input): Json<ServiceRegistration>,
) -> ApiResult<OkWire> {
    // Deliberately unauthenticated enrollment: ONLY for loopback integration tests.
    let mut server = lock(&state)?;
    server
        .register_service(input.service, input.public_key)
        .map_err(|_| StatusCode::CONFLICT)?;
    Ok(Json(OkWire { ok: true }))
}

async fn challenge(
    State(state): State<SharedServer>,
    Json(input): Json<ServiceQuery>,
) -> ApiResult<AuthWire> {
    let mut server = lock(&state)?;
    let req = server
        .issue_challenge(&input.service)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(AuthWire {
        version: req.version(),
        service: req.service().to_owned(),
        challenge: req.challenge(),
    }))
}

async fn login(
    State(state): State<SharedServer>,
    Json(input): Json<SignedAuthWire>,
) -> ApiResult<TokenWire> {
    let req = AuthRequest::new(input.version, input.service, input.challenge)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut server = lock(&state)?;
    let token = server
        .login(&req, &input.signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(TokenWire { token }))
}

async fn session_challenge(
    State(state): State<SharedServer>,
    Json(input): Json<ActionQuery>,
) -> ApiResult<ProofWire> {
    // Fixed action allowlist: this demo endpoint never initiates real-world actions.
    if input.action != "sensitive-demo-action" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut server = lock(&state)?;
    let req = server
        .issue_session_challenge(input.token, &input.action)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(ProofWire {
        version: req.version(),
        service: req.service().to_owned(),
        token: req.token(),
        action: req.action().to_owned(),
        challenge: req.challenge(),
    }))
}

async fn execute(
    State(state): State<SharedServer>,
    Json(input): Json<SignedProofWire>,
) -> ApiResult<OkWire> {
    let req = SessionProofRequest::new(
        input.version,
        input.service,
        input.token,
        input.action,
        input.challenge,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    if req.action() != "sensitive-demo-action" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut server = lock(&state)?;
    server
        .execute_sensitive(&req, &input.signature)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(OkWire { ok: true }))
}

async fn revoke(
    State(state): State<SharedServer>,
    Json(input): Json<TokenWire>,
) -> ApiResult<OkWire> {
    let mut server = lock(&state)?;
    server
        .revoke_session(input.token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json(OkWire { ok: true }))
}

/// Fully in-memory router; creation does not bind any socket.
pub fn router(server: MockServer) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/v1/register", post(register))
        .route("/v1/auth/challenge", post(challenge))
        .route("/v1/auth/login", post(login))
        .route("/v1/session/challenge", post(session_challenge))
        .route("/v1/session/execute", post(execute))
        .route("/v1/session/revoke", post(revoke))
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(middleware::from_fn(local_only))
        .with_state(Arc::new(Mutex::new(server)))
}
