# Aitanti — identidades persistentes cifradas (PoC)

## Alcance

Esta fase conserva las claves privadas P-256 de dos servicios **ficticios** entre ejecuciones del agente. Se mantiene el `http-demo` efímero y se añade un modo que lee claves cifradas. No cambia la versión del protocolo de autenticación ni el formato del vault de atributos personales.

El archivo de identidades tiene un formato independiente (`AITKEY01` + versión + salt + nonce + AES-256-GCM). El contenido cifrado incluye un contenedor versionado de claves PKCS#8 (`AITIDS01`). Las contraseñas pasan por Argon2id con los parámetros **fijos de la versión 1** del vault, y las escrituras usan `create_new` para impedir reemplazos silenciosos.

### Primer uso (WSL Ubuntu)

```bash
cd /home/santiago/Proyectos/Aitanti
mkdir -p -m 700 "$HOME/.local/share/aitanti"
cargo run -p aitanti-agent-cli -- keys-init "$HOME/.local/share/aitanti/demo-identities.aitk"
cargo run -p aitanti-agent-cli -- keys-check "$HOME/.local/share/aitanti/demo-identities.aitk"
```

En una terminal, deja el servidor de demostración abierto:

```bash
cargo run -p aitanti-mock-server
```

En una segunda terminal:

```bash
cargo run -p aitanti-agent-cli -- http-demo-persistent "$HOME/.local/share/aitanti/demo-identities.aitk"
```

Vuelve a ejecutar `http-demo-persistent` sin reiniciar el servidor: el mismo par de claves debe registrarse de manera idempotente. El servidor **rechaza** registrar otra clave para el mismo servicio. El servidor sigue almacenando solo claves públicas y sesiones efímeras.

La contraseña se pide sin eco y no se escribe en disco. Para esta prueba utiliza una frase **ficticia y distinta** de cualquier contraseña personal.

### Borrar los datos de prueba

Detén el servidor con `Ctrl+C` y luego:

```bash
rm -i "$HOME/.local/share/aitanti/demo-identities.aitk"
```

`rm` no garantiza borrado forense en SSD o máquinas virtuales; aquí se trata únicamente de material sintético. Conserva el directorio si lo utilizarás para próximas pruebas.

## Límites de seguridad

- **No hay TPM/Secure Enclave**, mecanismos anti-extracción de claves, bloqueo de memoria ni protección ante malware con acceso al proceso del agente.
- La contraseña es vulnerable a ataques offline si es fácil de adivinar. Doce caracteres por sí solos no garantizan entropía suficiente.
- La demo sigue admitiendo **registro de claves sin autenticación**. Solo es válida sobre `127.0.0.1` para pruebas. Un proceso malicioso local podría registrar antes una identidad. El servidor no conserva inscripciones tras reiniciarse.
- Las peticiones de sesión todavía firman un nombre de acción definido por el protocolo v1, pero **no enlazan todavía método HTTP, URL exacta ni hash del cuerpo**. Esa será una extensión versionada del protocolo; no se debe afirmar protección DPoP de producción.
- No se almacenan identidades reales ni contraseñas de servicios reales.

## Pruebas y aceptación

- `cargo fmt --all -- --check`
- `cargo check --workspace --all-targets --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --locked`
- `http-demo-persistent` funciona dos veces con la misma inscripción del servidor.
- `keys-init` rechaza sobrescribir un archivo existente, `keys-check` rechaza una contraseña incorrecta y las pruebas rechazan alteraciones de ciphertext.
- CodeQL en GitHub sin alertas nuevas bloqueantes.

No fusionar antes de comprobar lo anterior. El parche no se considera un sistema de identidad listo para producción.
