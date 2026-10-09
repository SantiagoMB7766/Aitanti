//! Demo listener, never bind this service to 0.0.0.0 or expose its open registration API.
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:8787").await?;
    println!("Aitanti DEMO HTTP server listening on 127.0.0.1:8787 (no production identities)");
    axum::serve(
        listener,
        aitanti_mock_server::http::router(aitanti_mock_server::MockServer::new()),
    )
    .await?;
    Ok(())
}
