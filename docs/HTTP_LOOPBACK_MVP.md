# Aitanti — Loopback HTTP MVP (demo only)

This iteration demonstrates two **independent processes** communicating via HTTP over `127.0.0.1`. It does not implement WebAuthn, a browser bridge, trusted enrollment, identity attestation or production authorization.

## Run on Ubuntu / WSL

```bash
# Terminal 1: start demo server (loopback only)
cd /home/santiago/Proyectos/Aitanti
cargo run -p aitanti-mock-server

# Terminal 2: run a transient agent, no passwords or real attributes
cd /home/santiago/Proyectos/Aitanti
cargo run -p aitanti-agent-cli -- http-demo
```

Expected agent results (without revealing tokens or private keys):

- Separate keys for `service-a.local` and `service-b.local` are registered with public keys only.
- A challenge is signed and verified; replay is rejected.
- An operation attempted with only the token is rejected.
- A correct signed operation succeeds once; replay fails.
- Explicit session revocation makes the session unusable.

**Restart terminal 1 to repeat the demo**: registrations and issued tokens live in memory, and a second run with freshly generated keys must not silently overwrite a prior registration.

To stop the server press `Ctrl+C` in terminal 1. No listening socket remains. The server never persists credentials or PII.

## HTTP operations (not a stable public SDK)

| Method | Path | Notes |
|---|---|---|
| GET | `/healthz` | Loopback health status, no credentials |
| POST | `/v1/register` | Demo-only, unenforced public-key registration; **not secure enrollment** |
| POST | `/v1/auth/challenge` | One-time authentication challenge |
| POST | `/v1/auth/login` | Versioned challenge, service and signature; returns session token |
| POST | `/v1/session/challenge` | Bound to token and `sensitive-demo-action` |
| POST | `/v1/session/execute` | Requires token, challenge and device signature |
| POST | `/v1/session/revoke` | Revokes session immediately |

Wire bodies are JSON for this demo only; the signature always covers the canonical **binary** bytes from `aitanti-protocol`, not a serialized JSON string. A standard-format Web SDK will require a separately versioned API specification, discovery and stronger origin/client authentication.

## Protections implemented

- Process binds to `127.0.0.1:8787`, not to a public interface.
- Server rejects unexpected `Host`, browser-originated requests and requests lacking `X-Aitanti-Demo-Client: 1`. No permissive CORS headers are returned. These are defense-in-depth filters, not local-client identity verification.
- JSON request bodies capped at 8 KiB; per-process registration, challenge and session counts are bounded.
- Challenges expire after 60 seconds; sessions expire after 10 minutes using monotonic time (`Instant`). Expired entries are pruned during requests.
- Signature verifications occur before challenge consumption; failed signatures do not burn valid challenges.
- Only the hard-coded `sensitive-demo-action` can be invoked through HTTP. It performs no transaction.
- HTTP client disables proxy lookup and redirects, only accesses a fixed loopback URL, and has a 5-second timeout.
- Integration tests open an ephemeral TCP listener and exercise the complete signed protocol over HTTP, plus browser-origin rejection.

## Known limitations — do not expose or use for real identities

1. **Registration is deliberately open** on loopback. Another local process could register first (or consume the finite resource pool). No trusted pairing and no enrolment/authentication policy is implemented yet.
2. **HTTP is unencrypted**, because this is an explicit localhost demo. Host/Origin checks and a custom header **do not stop malicious native processes**; malware with local privileges can connect and potentially interfere. There is no IPC authentication or OS keystore integration.
3. **Private keys are ephemeral and memory-resident.** This proves signatures, but not protected persistent keys, recovery, or hardware-backed non-exportability.
4. Session actions are bound to an action name, not to a canonical HTTP method/path/body digest. Do not repurpose this endpoint for payments or state-changing APIs.
5. The example has no cross-process lockout, global network rate limiter, tenant model or audit-ready telemetry. It is deliberately not a public service.
6. No zero-knowledge age proof: disclosure remains self-asserted in the earlier offline demo.

## Rust dependencies introduced and why

- `axum = 0.8.9`: safe and maintained HTTP routing, typed JSON extraction, body limit and middleware.
- `tokio = 1`: async I/O runtime needed by Axum.
- `serde = 1`: typed JSON demo message structures; **not** the signature serialization.
- `reqwest = 0.13.5`: real HTTP client, minimal features (JSON and blocking mode in CLI), with TLS/default proxy features disabled since the URL is fixed to loopback.

The previous crypto libraries and vault format remain unchanged.
