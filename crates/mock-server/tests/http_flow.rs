//! End-to-end test over a real local TCP listener, no production secrets.
use aitanti_crypto_core::ServiceKey;
use aitanti_mock_server::{
    MockServer,
    http::{
        ActionQuery, AuthWire, OkWire, ProofWire, ServiceQuery, ServiceRegistration,
        SignedAuthWire, SignedProofWire, TokenWire,
    },
};
use aitanti_protocol::{AuthRequest, SessionProofRequest};
use reqwest::StatusCode;

#[tokio::test]
async fn tcp_authentication_and_session_binding() -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            aitanti_mock_server::http::router(MockServer::new()),
        )
        .await
    });
    let client = reqwest::Client::builder().no_proxy().build()?;
    let base = format!("http://{address}");
    let key = ServiceKey::generate("service-a.local")?;

    assert!(
        client
            .post(format!("{base}/v1/register"))
            .header("x-aitanti-demo-client", "1")
            .json(&ServiceRegistration {
                service: key.service().into(),
                public_key: key.public_key_sec1()
            })
            .send()
            .await?
            .status()
            .is_success()
    );

    let challenge: AuthWire = client
        .post(format!("{base}/v1/auth/challenge"))
        .header("x-aitanti-demo-client", "1")
        .json(&ServiceQuery {
            service: key.service().into(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let auth = AuthRequest::new(challenge.version, challenge.service, challenge.challenge)?;
    let signed = SignedAuthWire {
        version: auth.version(),
        service: auth.service().into(),
        challenge: auth.challenge(),
        signature: key.sign_auth(&auth)?,
    };
    let token: TokenWire = client
        .post(format!("{base}/v1/auth/login"))
        .header("x-aitanti-demo-client", "1")
        .json(&signed)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        client
            .post(format!("{base}/v1/auth/login"))
            .header("x-aitanti-demo-client", "1")
            .json(&signed)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let p: ProofWire = client
        .post(format!("{base}/v1/session/challenge"))
        .header("x-aitanti-demo-client", "1")
        .json(&ActionQuery {
            token: token.token,
            action: "sensitive-demo-action".into(),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let proof = SessionProofRequest::new(p.version, p.service, p.token, p.action, p.challenge)?;
    let mut signed = SignedProofWire {
        version: proof.version(),
        service: proof.service().into(),
        token: proof.token(),
        action: proof.action().into(),
        challenge: proof.challenge(),
        signature: vec![],
    };
    assert_eq!(
        client
            .post(format!("{base}/v1/session/execute"))
            .header("x-aitanti-demo-client", "1")
            .json(&signed)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    signed.signature = key.sign_session(&proof)?;
    let granted: OkWire = client
        .post(format!("{base}/v1/session/execute"))
        .header("x-aitanti-demo-client", "1")
        .json(&signed)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert!(granted.ok);
    assert_eq!(
        client
            .post(format!("{base}/v1/session/execute"))
            .header("x-aitanti-demo-client", "1")
            .json(&signed)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    task.abort();
    Ok(())
}

#[tokio::test]
async fn web_origins_and_missing_client_header_are_denied() -> Result<(), Box<dyn std::error::Error>>
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            aitanti_mock_server::http::router(MockServer::new()),
        )
        .await
    });
    let client = reqwest::Client::builder().no_proxy().build()?;
    let base = format!("http://{address}");
    let request = ServiceQuery {
        service: "service-a.local".to_owned(),
    };
    assert_eq!(
        client
            .post(format!("{base}/v1/auth/challenge"))
            .json(&request)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        client
            .post(format!("{base}/v1/auth/challenge"))
            .header("origin", "https://attacker.example")
            .header("x-aitanti-demo-client", "1")
            .json(&request)
            .send()
            .await?
            .status(),
        StatusCode::FORBIDDEN
    );
    task.abort();
    Ok(())
}
