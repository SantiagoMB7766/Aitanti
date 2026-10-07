use std::error::Error;

use aitanti_crypto_core::ServiceKey;

fn main() -> Result<(), Box<dyn Error>> {
    let service_a = ServiceKey::generate("service-a.local")?;
    let service_b = ServiceKey::generate("service-b.local")?;

    if service_a.public_key_sec1() == service_b.public_key_sec1() {
        return Err("unexpected identical public identities".into());
    }

    println!("Aitanti agent crypto bootstrap: OK");
    println!("service-a.local identity: ready");
    println!("service-b.local identity: ready");
    println!("public identities are distinct");

    Ok(())
}
