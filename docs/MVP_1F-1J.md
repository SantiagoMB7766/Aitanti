# Aitanti — entrega 1F–1J (prototipo local)

## Alcance implementado

- `aitanti-vault`: perfil ficticio con nombre, fecha de nacimiento y dirección. Archivo cifrado/autenticado AES-256-GCM. Clave de 256 bits derivada mediante Argon2id, sal aleatoria de 16 bytes y nonce aleatorio de 12 bytes, nuevo por archivo.
- `aitanti-agent-core`: autorización local explícita de una sola vez para compartir `age_over_18` o `shipping_address`. Denegación por defecto.
- `aitanti-protocol`: preimagen canónica distinta para la firma de operación sensible: dominio `aitanti/session-proof`, versión, servicio, token de 32 bytes, acción y nonce de 32 bytes.
- `aitanti-crypto-core`: firma y verificación ECDSA P-256/SHA-256 para operaciones de sesión.
- `aitanti-mock-server`: login autenticado que emite token de sesión; una acción sensible requiere challenge único y firma de la clave registrada. Replays rechazados. Todo en memoria.
- `aitanti-agent-cli`: subcomandos `demo`, `vault-init` y `vault-check`, sin mostrar la passphrase ni los valores personales.

## Comandos

Desde `/home/santiago/Proyectos/Aitanti`:

```bash
cargo fmt --all
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p aitanti-agent-cli -- demo
```

El demo pide una passphrase temporal no visible y solicita confirmación explícita (`YES`) para revelar atributos. No graba archivos. Para probar persistencia **solo con datos ficticios**:

```bash
mkdir -p -m 700 "$HOME/.local/share/aitanti"
cargo run -p aitanti-agent-cli -- vault-init "$HOME/.local/share/aitanti/demo.vault"
cargo run -p aitanti-agent-cli -- vault-check "$HOME/.local/share/aitanti/demo.vault"
ls -l "$HOME/.local/share/aitanti/demo.vault"
```

El archivo debe tener permisos `-rw-------`. Borra la demo después de comprobar que funciona:

```bash
rm -i "$HOME/.local/share/aitanti/demo.vault"
```

No se sobreescriben archivos existentes. No guardes **ningún dato real** ni ninguna clave de uso personal aquí todavía.

## Decisiones criptográficas

- AES-256-GCM (`aws-lc-rs`): autenticidad y confidencialidad; AAD incluye cabecera con magic, versión, sal y nonce.
- Argon2id (`argon2`): 64 MiB, 3 pasadas, 1 lane y salida de 32 bytes. Estos parámetros están fijados al formato 1, que no implementa migraciones.
- Sal y nonce nuevos por archivo. Solo se cifra una vez por clave derivada; antes de permitir actualización/reescritura se deberá diseñar rotación segura.
- `zeroize` permite borrar buffers sensibles donde es posible. No garantiza eliminar todas las copias de la memoria del proceso ni impedir ataques de malware local.
- `rpassword` captura la passphrase sin mostrarla en la terminal.
- `serde` y `serde_json` serializan el perfil antes de cifrarlo; la serialización no define el protocolo de firma.
- `tempfile` se usa exclusivamente en tests de filesystem y se elimina automáticamente.

## Límites de seguridad (NO listo para producción)

1. **Demo sin HTTP**: cliente y mock-server están en el mismo proceso. No hemos implementado un SDK web, origins del navegador, HTTPS, WebAuthn ni DBSC/DPoP real.
2. **Session binding básico**: operaciones firmadas con nonce por acción; no hay caducidad, revocación, rate limiting, límites de sesiones ni vinculación a método URL/hash del cuerpo de una petición HTTP. Hay que añadirlo antes de exponer red.
3. **Modelo de servidor simplificado**: el mock-server registra una única clave por servicio, no diferentes usuarios dentro del mismo servicio; falta almacenar `(service, account_id, credential_id)`.
4. **Vault MVP**: los archivos solo pueden crearse y leerse, no actualizarse ni recuperarse. Falta protección más estricta de acceso al fichero, contra TOCTOU, copias de seguridad, rotación y gestión segura de claves persistentes. La clave de firma `ServiceKey` sigue siendo efímera y no se almacena en el vault.
5. **Atributo de edad**: `age_over_18` es una **afirmación local**, no una prueba ZK ni una credencial verificable por tercero sin confiar en el usuario. Nunca describirla como prueba criptográfica ante una web.
6. **Consentimiento**: la CLI necesita confirmación, pero todavía no existe una frontera de seguridad que impida a código local malicioso llamar a la API de `ApproveOnce`. Integración con el agente aislado después.
7. **Privacidad local**: Argon2id y AEAD mitigan ataques sobre una copia del fichero, pero una passphrase débil o malware sobre el equipo pueden comprometerlo. No se garantiza invulnerabilidad.
8. **Falta de compilación independiente**: la entrega debe superar `cargo check`, Clippy, tests y CodeQL en Ubuntu/GitHub antes del merge. No afirmar éxito antes de las pruebas del entorno del usuario.

## Próximo avance

Crear un servidor HTTP exclusivamente en loopback con identidad por cuenta/servicio, acciones vinculadas a `method + path + body hash + nonce`, pruebas interoperables, expiraciones, y pruebas de integración sobre sockets. Después almacenamiento y recuperación seguras de claves de servicio y control de consentimiento resistente a procesos externos.
