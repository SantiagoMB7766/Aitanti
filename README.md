# Aitanti — Iteration 1 starter

This repository is only the Rust workspace scaffold for the first cryptographic proof of concept.

## Scope of iteration 1

Build the canonical authentication message before adding signatures or networking.

The signed message will eventually bind:

- Aitanti authentication domain/context
- protocol version
- relying service/origin
- one-time 32-byte challenge

## First task

Implement `crates/protocol/src/lib.rs` with:

1. a typed `ProtocolError`;
2. an `AuthRequest` containing protocol version, service/origin and `[u8; 32]` challenge;
3. `signing_bytes()` returning deterministic and unambiguous bytes;
4. unit tests proving:
   - same request -> same bytes;
   - same challenge, different service -> different bytes;
   - same service, different challenge -> different bytes;
   - empty service -> error.

Do not add cryptographic crates yet.

## Basic checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```
