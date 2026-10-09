//! Explicit, non-persistent loopback-only demonstration of the external protocol.
use std::{error::Error, time::Duration};

use aitanti_crypto_core::ServiceKey;
use aitanti_mock_server::http::{
    ActionQuery, AuthWire, OkWire, ProofWire, ServiceQuery, ServiceRegistration, SignedAuthWire,
    SignedProofWire, TokenWire,
};
use aitanti_protocol::{AuthRequest, SessionProofRequest};
use reqwest::{StatusCode, blocking::Client};

const BASE: &str = "http://127.0.0.1:8787";

pub fn run() -> Result<(), Box<dyn Error>> {
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let ok = client
        .get(format!("{BASE}/healthz"))
        .send()?
        .error_for_status()?;
    if !ok.json::<OkWire>()?.ok {
        return Err("demo server not healthy".into());
    }

    let key_a = ServiceKey::generate("service-a.local")?;
    let key_b = ServiceKey::generate("service-b.local")?;
    if key_a.public_key_sec1() == key_b.public_key_sec1() {
        return Err("identity separation failed".into());
    }

    for key in [&key_a, &key_b] {
        client
            .post(format!("{BASE}/v1/register"))
            .header("x-aitanti-demo-client", "1")
            .json(&ServiceRegistration {
                service: key.service().to_owned(),
                public_key: key.public_key_sec1(),
            })
            .send()?
            .error_for_status()?;
    }
    println!("HTTP: distinct service identities enrolled (public keys only).");

    let wire: AuthWire = client
        .post(format!("{BASE}/v1/auth/challenge"))
        .header("x-aitanti-demo-client", "1")
        .json(&ServiceQuery {
            service: key_a.service().to_owned(),
        })
        .send()?
        .error_for_status()?
        .json()?;
    let auth = AuthRequest::new(wire.version, wire.service, wire.challenge)?;
    let signed = SignedAuthWire {
        version: auth.version(),
        service: auth.service().to_owned(),
        challenge: auth.challenge(),
        signature: key_a.sign_auth(&auth)?,
    };
    let token: TokenWire = client
        .post(format!("{BASE}/v1/auth/login"))
        .header("x-aitanti-demo-client", "1")
        .json(&signed)
        .send()?
        .error_for_status()?
        .json()?;
    let replay = client
        .post(format!("{BASE}/v1/auth/login"))
        .header("x-aitanti-demo-client", "1")
        .json(&signed)
        .send()?;
    if replay.status() != StatusCode::UNAUTHORIZED {
        return Err("authentication replay accepted".into());
    }
    println!("HTTP: authentication passed and replay rejected.");

    let wire: ProofWire = client
        .post(format!("{BASE}/v1/session/challenge"))
        .header("x-aitanti-demo-client", "1")
        .json(&ActionQuery {
            token: token.token,
            action: "sensitive-demo-action".into(),
        })
        .send()?
        .error_for_status()?
        .json()?;
    let proof = SessionProofRequest::new(
        wire.version,
        wire.service,
        wire.token,
        wire.action,
        wire.challenge,
    )?;
    let mut submitted = SignedProofWire {
        version: proof.version(),
        service: proof.service().to_owned(),
        token: proof.token(),
        action: proof.action().to_owned(),
        challenge: proof.challenge(),
        signature: Vec::new(),
    };
    let unsigned = client
        .post(format!("{BASE}/v1/session/execute"))
        .header("x-aitanti-demo-client", "1")
        .json(&submitted)
        .send()?;
    if unsigned.status() != StatusCode::UNAUTHORIZED {
        return Err("stolen token accepted".into());
    }

    submitted.signature = key_a.sign_session(&proof)?;
    client
        .post(format!("{BASE}/v1/session/execute"))
        .header("x-aitanti-demo-client", "1")
        .json(&submitted)
        .send()?
        .error_for_status()?;
    let replay = client
        .post(format!("{BASE}/v1/session/execute"))
        .header("x-aitanti-demo-client", "1")
        .json(&submitted)
        .send()?;
    if replay.status() != StatusCode::UNAUTHORIZED {
        return Err("session replay accepted".into());
    }
    println!("HTTP: token-only rejected, signed action accepted once, replay rejected.");

    client
        .post(format!("{BASE}/v1/session/revoke"))
        .header("x-aitanti-demo-client", "1")
        .json(&token)
        .send()?
        .error_for_status()?;
    let revoked = client
        .post(format!("{BASE}/v1/session/challenge"))
        .header("x-aitanti-demo-client", "1")
        .json(&ActionQuery {
            token: token.token,
            action: "sensitive-demo-action".into(),
        })
        .send()?;
    if revoked.status() != StatusCode::UNAUTHORIZED {
        return Err("revoked session accepted".into());
    }
    println!("HTTP: logout revoked the session; no private keys or tokens persisted.");
    Ok(())
}
