// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TPM 2.0 interface for Azure Guest Attestation.
//!
//! This module provides a comprehensive TPM 2.0 interface for confidential virtual machine
//! (CVM) attestation workflows. It includes:
//!
//! - **Device access** ([`device`]): Platform-agnostic TPM device communication
//! - **Commands** ([`commands`]): High-level TPM command implementations via [`TpmCommandExt`]
//! - **Types** ([`types`]): TPM 2.0 data structures and marshaling
//! - **Attestation** ([`attestation`]): CVM-specific attestation operations
//! - **Helpers** ([`helpers`]): Internal utilities for command building
//! - **Event log** ([`event_log`]): TCG event log parsing
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │           Attestation APIs              │
//! │  (get_cvm_report, get_pcr_quote, etc.)  │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │         TpmCommandExt Trait             │
//! │  (create_primary, sign, quote, etc.)    │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │           RawTpm Trait                  │
//! │        (transmit_raw bytes)             │
//! └─────────────────┬───────────────────────┘
//!                   │
//! ┌─────────────────▼───────────────────────┐
//! │    Platform TPM Driver / vTPM / Ref     │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use azure_guest_attestation_sdk::tpm::{Tpm, TpmCommandExt};
//!
//! // Open the platform TPM
//! let tpm = Tpm::open()?;
//!
//! // Read PCR values
//! let pcrs = tpm.read_pcrs_sha256(&[0, 1, 2, 7])?;
//! for (index, digest) in &pcrs {
//!     println!("PCR{}: {}", index, hex::encode(digest));
//! }
//! ```

pub mod attestation;
pub mod commands;
pub mod device;
pub mod event_log;
pub mod helpers;
pub mod types;

pub use commands::TpmCommandExt;
pub use device::{RawTpm, Tpm};
pub use types::TpmCommandCode;
