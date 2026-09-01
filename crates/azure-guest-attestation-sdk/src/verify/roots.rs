// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pinned AMD SEV root keys (ARK) used as trust anchors for VCEK chains.
//!
//! Sourced from the AMD Key Distribution Service (`kdsintf.amd.com`). Pinning
//! the root — rather than trusting whatever root a caller supplies — is what
//! anchors SEV-SNP verification to AMD.

use super::crypto::{cert_from_pem, Cert};
use std::io;

/// ARK-Milan root. SHA-256 fingerprint:
/// `69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD`
const ARK_MILAN_PEM: &str = include_str!("roots/ark-milan.pem");

/// ARK-Genoa root. SHA-256 fingerprint:
/// `4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1`
const ARK_GENOA_PEM: &str = include_str!("roots/ark-genoa.pem");

/// ARK-Turin root. SHA-256 fingerprint:
/// `1F:08:41:61:A4:4B:B6:D9:37:78:A9:04:87:7D:48:19:CA:FA:5D:05:EF:41:93:B2:DE:D9:DD:9C:73:DD:3F:6A`
const ARK_TURIN_PEM: &str = include_str!("roots/ark-turin.pem");

/// Intel SGX Provisioning Certification Root CA. SHA-256 fingerprint:
/// `44:A0:19:6B:2B:99:F8:89:B8:E1:49:E9:5B:80:7A:35:0E:74:24:96:43:99:E8:85:A7:CB:B8:CC:FA:B6:74:D3`
const INTEL_SGX_ROOT_PEM: &str = include_str!("roots/intel-sgx-root.pem");

/// Parse and return the pinned AMD ARK trust anchors (Milan, Genoa, Turin).
pub(crate) fn amd_ark_roots() -> io::Result<Vec<Cert>> {
    [ARK_MILAN_PEM, ARK_GENOA_PEM, ARK_TURIN_PEM]
        .iter()
        .map(|pem| {
            cert_from_pem(pem.as_bytes())
                .map_err(|e| io::Error::other(format!("parse pinned ARK root: {e}")))
        })
        .collect()
}

/// Parse and return the pinned Intel SGX Root CA trust anchor.
pub(crate) fn intel_sgx_root() -> io::Result<Cert> {
    cert_from_pem(INTEL_SGX_ROOT_PEM.as_bytes())
        .map_err(|e| io::Error::other(format!("parse pinned Intel SGX root: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_ark_roots_parse_and_are_self_signed() {
        let roots = amd_ark_roots().expect("ARK roots parse");
        assert_eq!(roots.len(), 3);
        for root in &roots {
            // Each ARK is a self-signed root.
            assert!(super::super::crypto::cert_is_self_signed(root));
        }
    }

    #[test]
    fn pinned_intel_root_parses_and_is_self_signed() {
        let root = intel_sgx_root().expect("Intel SGX root parses");
        assert!(super::super::crypto::cert_is_self_signed(&root));
    }
}
