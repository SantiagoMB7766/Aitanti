//! Public protocol types for Aitanti.
//!
//! Iteration 1 exercise:
//! - model the authentication request that will later be signed;
//! - bind it to protocol version + service/origin + challenge;
//! - expose a deterministic, unambiguous byte representation;
//! - return typed errors instead of panicking.
//!
//! Do not add cryptography here yet.

// TODO(iteration-1): implement ProtocolError.
// TODO(iteration-1): implement AuthRequest.
// TODO(iteration-1): implement AuthRequest::signing_bytes().
// TODO(iteration-1): add unit tests for deterministic encoding and service/challenge separation.
