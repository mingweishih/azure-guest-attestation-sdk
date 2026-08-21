// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local (offline) attestation verification.
//!
//! Cryptographically validates attestation evidence without a round-trip to
//! MAA: certificate-chain validation to a pinned hardware root and signature
//! verification of the report/quote.
//!
//! Gated behind the `verify` feature, which requires the `native` crypto
//! backend. Currently Linux-only (system OpenSSL); Windows (CNG + crypt32)
//! support is pending.

#[cfg(not(target_os = "linux"))]
compile_error!(
    "the `verify` feature currently requires Linux (OpenSSL); Windows (CNG/crypt32) support is pending"
);

mod crypto;
mod roots;
pub mod snp;

pub use snp::{verify_snp_report, SnpVerifyPolicy, SnpVerifyResult};
