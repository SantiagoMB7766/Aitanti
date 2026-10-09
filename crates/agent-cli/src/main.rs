//! Aitanti CLI: offline and local HTTP demonstrations using fictitious data.

mod http_demo;

use std::{
    env,
    error::Error,
    io::{self, Write},
    path::Path,
};

use aitanti_agent_core::{Attribute, DisclosureRequest, ReleasedAttribute, UserDecision, disclose};
use aitanti_crypto_core::ServiceKey;
use aitanti_mock_server::MockServer;
use aitanti_vault::{Date, Profile, create_new, open, read_file, seal};
use zeroize::Zeroizing;

fn password(prompt: &str) -> Result<Zeroizing<String>, Box<dyn Error>> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn approve(request: &DisclosureRequest) -> Result<UserDecision, Box<dyn Error>> {
    println!("Service: {}", request.service);
    println!("Purpose: {}", request.purpose);
    println!("Requested attribute: {:?}", request.attribute);
    print!("Allow once? Type YES: ");
    io::stdout().flush()?;
    let mut response = String::new();
    io::stdin().read_line(&mut response)?;
    Ok(if response.trim() == "YES" {
        UserDecision::ApproveOnce
    } else {
        UserDecision::Deny
    })
}

fn run_demo() -> Result<(), Box<dyn Error>> {
    println!("Aitanti offline security demonstration (synthetic data only)");
    let passphrase = password("Temporary demo passphrase (12+ bytes, not stored): ")?;
    let original = Profile::fictitious();
    let envelope = seal(&original, &passphrase)?;
    let profile = open(&envelope, &passphrase)?;
    println!("Vault encrypted and authenticated in memory; no disk file created.");

    let key_a = ServiceKey::generate("service-a.local")?;
    let key_b = ServiceKey::generate("service-b.local")?;
    if key_a.public_key_sec1() == key_b.public_key_sec1() {
        return Err("duplicate public identities".into());
    }
    println!("Per-service public identities differ.");

    let date = Date::new(2026, 10, 8)?;
    let request_a = DisclosureRequest::new("service-a.local", "age check", Attribute::AgeOver18)?;
    let answer_a = disclose(&profile, &request_a, approve(&request_a)?, date)?;
    match answer_a {
        Some(ReleasedAttribute::AgeOver18(value)) => {
            println!("Service A: age_over_18={value} (self-assertion, not a ZK proof)")
        }
        _ => println!("Service A: disclosure denied"),
    }

    let request_b = DisclosureRequest::new(
        "service-b.local",
        "deliver demo order",
        Attribute::ShippingAddress,
    )?;
    let answer_b = disclose(&profile, &request_b, approve(&request_b)?, date)?;
    match answer_b {
        Some(ReleasedAttribute::ShippingAddress(_)) => {
            println!("Service B: address authorized (value intentionally not printed)")
        }
        _ => println!("Service B: disclosure denied"),
    }

    let mut server = MockServer::new();
    server.register_service("service-a.local", key_a.public_key_sec1())?;
    server.register_service("service-b.local", key_b.public_key_sec1())?;
    let auth = server.issue_challenge("service-a.local")?;
    let auth_signature = key_a.sign_auth(&auth)?;
    let session_token = server.login(&auth, &auth_signature)?;
    let request = server.issue_session_challenge(session_token, "sensitive-demo-action")?;
    if server.execute_sensitive(&request, &[]).is_ok() {
        return Err("security invariant failed: unsigned token was accepted".into());
    }
    let signed_proof = key_a.sign_session(&request)?;
    server.execute_sensitive(&request, &signed_proof)?;
    if server.execute_sensitive(&request, &signed_proof).is_ok() {
        return Err("security invariant failed: replay was accepted".into());
    }
    println!("Stolen token alone: rejected. Signed proof: accepted once. Replay: rejected.");
    println!("Demo completed; no local credentials, token or vault persisted.");
    Ok(())
}

fn create_vault(path: &Path) -> Result<(), Box<dyn Error>> {
    let first = password("New demo-vault passphrase (12+ bytes): ")?;
    let second = password("Repeat passphrase: ")?;
    if first.as_str() != second.as_str() {
        return Err("passphrases did not match".into());
    }
    create_new(path, &Profile::fictitious(), &first)?;
    println!("Encrypted fixture vault created; values were not printed. Never use real data yet.");
    Ok(())
}

fn check_vault(path: &Path) -> Result<(), Box<dyn Error>> {
    let passphrase = password("Vault passphrase: ")?;
    let _profile = read_file(path, &passphrase)?;
    println!("Vault authenticated and decrypted (attribute values hidden).");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = env::args().collect();
    match arguments.as_slice() {
        [_program, command] if command == "demo" => run_demo(),
        [_program, command] if command == "http-demo" => http_demo::run(),
        [_program, command, path] if command == "vault-init" => create_vault(Path::new(path)),
        [_program, command, path] if command == "vault-check" => check_vault(Path::new(path)),
        _ => {
            println!(
                "Usage:\n  aitanti-agent-cli demo\n  aitanti-agent-cli http-demo\n  aitanti-agent-cli vault-init <path>\n  aitanti-agent-cli vault-check <path>"
            );
            Ok(())
        }
    }
}
