// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local (offline) attestation verification.
//!
//! Cryptographically validates attestation evidence without a round-trip to
//! MAA: certificate-chain validation to a pinned hardware root and signature
//! verification of the report/quote.
//!
//! Gated behind the `verify` feature, which requires the `native` crypto
//! backend: system OpenSSL on Linux, CNG (BCrypt) + CryptoAPI (crypt32) on
//! Windows.

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("the `verify` feature requires Linux (OpenSSL) or Windows (CNG/crypt32)");

mod crypto;
mod roots;
pub mod snp;
pub mod snp_id_block;
pub mod tdx;

pub use snp::{verify_snp_report, SnpMeasurements, SnpVerifyPolicy, SnpVerifyResult};
pub use snp_id_block::{verify_snp_id_block, SnpIdBlockVerifyResult};
pub use tdx::{verify_td_quote, TdxMeasurements, TdxVerifyPolicy, TdxVerifyResult};
