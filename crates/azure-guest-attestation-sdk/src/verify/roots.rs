// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pinned AMD SEV root keys (ARK) used as trust anchors for VCEK chains.
//!
//! Sourced from the AMD Key Distribution Service (`kdsintf.amd.com`). Pinning
//! the root — rather than trusting whatever root a caller supplies — is what
//! anchors SEV-SNP verification to AMD.

use openssl::x509::X509;
use std::io;

/// ARK-Milan root. SHA-256 fingerprint:
/// `69:D0:63:B4:53:44:D2:6A:2E:94:E1:F4:21:0D:E4:9E:F5:55:30:82:87:D4:C1:74:44:5C:95:63:9A:54:0B:CD`
const ARK_MILAN_PEM: &str = include_str!("roots/ark-milan.pem");

/// ARK-Genoa root. SHA-256 fingerprint:
/// `4C:65:98:D1:9C:18:71:9C:5D:FD:4A:7D:33:5F:67:4E:5B:FE:1D:8F:80:0C:EA:2C:F2:70:C1:0D:10:3D:B2:F1`
const ARK_GENOA_PEM: &str = include_str!("roots/ark-genoa.pem");

/// Parse and return the pinned AMD ARK trust anchors (Milan, Genoa).
pub(crate) fn amd_ark_roots() -> io::Result<Vec<X509>> {
    [ARK_MILAN_PEM, ARK_GENOA_PEM]
        .iter()
        .map(|pem| {
            X509::from_pem(pem.as_bytes())
                .map_err(|e| io::Error::other(format!("parse pinned ARK root: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_ark_roots_parse_and_are_self_signed() {
        let roots = amd_ark_roots().expect("ARK roots parse");
        assert_eq!(roots.len(), 2);
        for root in &roots {
            // Each ARK is a self-signed root.
            assert_eq!(root.issued(root), openssl::x509::X509VerifyResult::OK);
        }
    }
}
