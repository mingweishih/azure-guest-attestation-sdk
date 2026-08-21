// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Local verification of AMD SEV-SNP attestation reports.
//!
//! Validates the VCEK certificate chain to a pinned AMD ARK root and verifies
//! the report signature (ECDSA P-384 / SHA-384) under the VCEK public key.

use super::{crypto, roots};
use crate::tee_report::snp::{SnpReport, SNP_REPORT_SIZE};
use openssl::hash::MessageDigest;
use openssl::x509::{X509VerifyResult, X509};
use std::io;

/// Number of leading report bytes covered by the signature (everything before
/// the 512-byte signature field).
const SNP_SIGNED_LEN: usize = 0x2A0;
/// Size of each ECDSA component (`r`, `s`) in the SNP signature field
/// (little-endian, zero-padded).
const SNP_SIG_COMPONENT_LEN: usize = 72;

/// Policy controls for [`verify_snp_report`]. Reserved for TCB/policy options
/// added in a later phase; the current slice validates chain + signature only.
#[derive(Clone, Copy, Debug, Default)]
#[non_exhaustive]
pub struct SnpVerifyPolicy {}

/// Key measurements extracted from a verified SNP report.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SnpMeasurements {
    /// Launch measurement of the guest.
    pub measurement: [u8; 48],
    /// Report data (guest-provided).
    pub report_data: [u8; 64],
    /// Reported TCB version (AMD `TCB_VERSION`, little-endian u64).
    pub reported_tcb: u64,
    /// Chip identifier (0 if MaskChipId was set).
    pub chip_id: [u8; 64],
}

/// Outcome of verifying an SNP report.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct SnpVerifyResult {
    /// The VCEK certificate chain validated to a pinned AMD ARK root.
    pub chain_valid: bool,
    /// The report signature verified under the VCEK public key.
    pub signature_valid: bool,
    /// The measurements extracted from the verified report.
    pub measurements: SnpMeasurements,
}

/// Verify an AMD SEV-SNP attestation report against a VCEK certificate chain.
///
/// - `report_bytes`: the raw `0x4a0`-byte SNP attestation report.
/// - `vcek_chain_pem`: the VCEK leaf followed by the ASK (and optionally the
///   ARK) in PEM form, as returned by Azure IMDS/THIM or AMD KDS.
///
/// The chain is validated to a **pinned** AMD ARK root and the report signature
/// (ECDSA P-384 / SHA-384 over `report_bytes[..0x2A0]`) is checked under the
/// VCEK public key. Returns an error if either check fails.
pub fn verify_snp_report(
    report_bytes: &[u8],
    vcek_chain_pem: &[u8],
    policy: &SnpVerifyPolicy,
) -> io::Result<SnpVerifyResult> {
    let roots = roots::amd_ark_roots()?;
    verify_snp_report_with_roots(report_bytes, vcek_chain_pem, &roots, policy)
}

/// [`verify_snp_report`] against an explicit set of trusted roots. Exposed for
/// testing with a synthetic ARK; production callers use [`verify_snp_report`].
pub(crate) fn verify_snp_report_with_roots(
    report_bytes: &[u8],
    vcek_chain_pem: &[u8],
    roots: &[X509],
    _policy: &SnpVerifyPolicy,
) -> io::Result<SnpVerifyResult> {
    if report_bytes.len() < SNP_REPORT_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SNP report too short: {} < {SNP_REPORT_SIZE}",
                report_bytes.len()
            ),
        ));
    }

    // 1. Parse the VCEK chain: leaf = VCEK, remainder = intermediates.
    let chain = crypto::parse_pem_chain(vcek_chain_pem)?;
    let (vcek, rest) = chain.split_first().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "empty VCEK certificate chain")
    })?;

    // 2. Validate VCEK -> ASK -> pinned ARK. Drop any self-signed cert from the
    //    supplied intermediates so trust is anchored only on the pinned roots.
    let intermediates: Vec<X509> = rest
        .iter()
        .filter(|c| c.issued(c) != X509VerifyResult::OK)
        .cloned()
        .collect();
    crypto::verify_cert_chain(vcek, &intermediates, roots)?;

    // 3. Verify the report signature (ECDSA P-384 / SHA-384).
    let signed = &report_bytes[..SNP_SIGNED_LEN];
    let sig = &report_bytes[SNP_SIGNED_LEN..SNP_SIGNED_LEN + 512];
    let r_be = le_to_be(&sig[..SNP_SIG_COMPONENT_LEN]);
    let s_be = le_to_be(&sig[SNP_SIG_COMPONENT_LEN..2 * SNP_SIG_COMPONENT_LEN]);
    let signature_valid =
        crypto::ecdsa_verify_raw(vcek, MessageDigest::sha384(), signed, &r_be, &s_be)?;
    if !signature_valid {
        return Err(io::Error::other("SNP report signature verification failed"));
    }

    // Safety: length checked >= SNP_REPORT_SIZE above; read unaligned.
    let report: SnpReport =
        unsafe { core::ptr::read_unaligned(report_bytes.as_ptr() as *const SnpReport) };
    let measurements = SnpMeasurements {
        measurement: report.measurement,
        report_data: report.report_data,
        reported_tcb: report.reported_tcb,
        chip_id: report.chip_id,
    };

    Ok(SnpVerifyResult {
        chain_valid: true,
        signature_valid: true,
        measurements,
    })
}

/// Reverse a little-endian integer buffer to big-endian (as OpenSSL expects).
fn le_to_be(le: &[u8]) -> Vec<u8> {
    let mut v = le.to_vec();
    v.reverse();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::hash::hash;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::extension::BasicConstraints;
    use openssl::x509::{X509Builder, X509NameBuilder};

    fn p384_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn cert(
        cn: &str,
        subject_key: &PKey<Private>,
        issuer_cn: &str,
        issuer_key: &PKey<Private>,
        ca: bool,
    ) -> X509 {
        let mut sn = X509NameBuilder::new().unwrap();
        sn.append_entry_by_text("CN", cn).unwrap();
        let sn = sn.build();
        let mut inb = X509NameBuilder::new().unwrap();
        inb.append_entry_by_text("CN", issuer_cn).unwrap();
        let inb = inb.build();
        let mut b = X509Builder::new().unwrap();
        b.set_pubkey(subject_key).unwrap();
        b.set_subject_name(&sn).unwrap();
        b.set_issuer_name(&inb).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        if ca {
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
        }
        b.sign(issuer_key, MessageDigest::sha384()).unwrap();
        b.build()
    }

    /// Build a synthetic ARK->ASK->VCEK chain mirroring AMD's structure and a
    /// report signed by the VCEK key, then exercise the full verify path.
    fn synthetic_case() -> (Vec<u8>, Vec<u8>, X509, PKey<Private>) {
        let ark_key = p384_key();
        let ask_key = p384_key();
        let vcek_key = p384_key();

        let ark = cert("ARK-Test", &ark_key, "ARK-Test", &ark_key, true);
        let ask = cert("SEV-Test", &ask_key, "ARK-Test", &ark_key, true);
        let vcek = cert("VCEK-Test", &vcek_key, "SEV-Test", &ask_key, false);

        // Chain PEM: VCEK then ASK (ARK is the pinned root, supplied separately).
        let mut chain_pem = vcek.to_pem().unwrap();
        chain_pem.extend_from_slice(&ask.to_pem().unwrap());

        // Report: 0x4a0 bytes; sign SHA-384 of [0..0x2A0] with the VCEK key.
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[..SNP_SIGNED_LEN]
            .iter_mut()
            .enumerate()
            .for_each(|(i, b)| *b = (i % 251) as u8);
        let dgst = hash(MessageDigest::sha384(), &report[..SNP_SIGNED_LEN]).unwrap();
        let ec = vcek_key.ec_key().unwrap();
        let sig = EcdsaSig::sign(&dgst, &ec).unwrap();
        place_le(&mut report, SNP_SIGNED_LEN, &sig.r().to_vec());
        place_le(
            &mut report,
            SNP_SIGNED_LEN + SNP_SIG_COMPONENT_LEN,
            &sig.s().to_vec(),
        );

        (report, chain_pem, ark, vcek_key)
    }

    /// Store a big-endian integer as a 72-byte little-endian component at `off`.
    fn place_le(report: &mut [u8], off: usize, be: &[u8]) {
        let mut le = be.to_vec();
        le.reverse();
        le.resize(SNP_SIG_COMPONENT_LEN, 0);
        report[off..off + SNP_SIG_COMPONENT_LEN].copy_from_slice(&le);
    }

    #[test]
    fn verifies_valid_synthetic_report_and_chain() {
        let (report, chain_pem, ark, _) = synthetic_case();
        let res = verify_snp_report_with_roots(
            &report,
            &chain_pem,
            std::slice::from_ref(&ark),
            &SnpVerifyPolicy::default(),
        )
        .expect("verify ok");
        assert!(res.chain_valid && res.signature_valid);
    }

    #[test]
    fn rejects_tampered_report_body() {
        let (mut report, chain_pem, ark, _) = synthetic_case();
        report[0] ^= 0xff; // change a signed byte
        let err = verify_snp_report_with_roots(
            &report,
            &chain_pem,
            std::slice::from_ref(&ark),
            &SnpVerifyPolicy::default(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_untrusted_root() {
        let (report, chain_pem, _ark, _) = synthetic_case();
        // A different, unrelated ARK is not a trust anchor for this chain.
        let other = cert("ARK-Other", &p384_key(), "ARK-Other", &p384_key(), true);
        let err = verify_snp_report_with_roots(
            &report,
            &chain_pem,
            std::slice::from_ref(&other),
            &SnpVerifyPolicy::default(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn rejects_short_report() {
        let (_r, chain_pem, ark, _) = synthetic_case();
        let err = verify_snp_report_with_roots(
            &[0u8; 16],
            &chain_pem,
            std::slice::from_ref(&ark),
            &SnpVerifyPolicy::default(),
        );
        assert!(err.is_err());
    }

    /// End-to-end against a real SEV-SNP report + VCEK chain captured from an
    /// Azure CVM (AMD Turin). Validates to the *pinned* production ARK-Turin
    /// root and asserts the extracted measurements match the MAA token issued
    /// for the same report.
    #[test]
    fn verifies_real_turin_report() {
        let report = include_bytes!("testdata/snp_report_turin.bin");
        let chain = include_bytes!("testdata/snp_vcek_chain_turin.pem");
        let res = verify_snp_report(report, chain, &SnpVerifyPolicy::default())
            .expect("real SNP report verifies against pinned ARK-Turin");
        assert!(res.chain_valid);
        assert!(res.signature_valid);

        let m = res.measurements;
        assert_eq!(
            hex(&m.measurement),
            "12d40f252f43d99d78b15197400e266bd6b323c93d8fdfb61ccf2f30761d8708bc2f4b6dbcb8d3d769cd535c695938ab"
        );
        assert_eq!(
            hex(&m.report_data[..32]),
            "ab6a63f751fbf354f2bb6a3c12336e18caa1217c3d3b2cdcf57ffe2c21f69088"
        );
        // chip_id low 8 bytes == MAA x-ms-sevsnpvm-chipid.
        assert_eq!(hex(&m.chip_id[..8]), "5b0f3945c57a2338");
        // reported_tcb little-endian u64 == 0x5a0000_0005020301.
        assert_eq!(m.reported_tcb, 0x5a00_0000_0502_0301);
    }

    /// End-to-end against a real SEV-SNP report from an AMD **Milan** CVM (v3
    /// report format), with a VCEK chain fetched from AMD KDS. Validates to the
    /// *pinned* ARK-Milan root, exercising a different chip generation and
    /// report version than the Turin case.
    #[test]
    fn verifies_real_milan_report() {
        let report = include_bytes!("testdata/snp_report_milan.bin");
        let chain = include_bytes!("testdata/snp_vcek_chain_milan.pem");
        let res = verify_snp_report(report, chain, &SnpVerifyPolicy::default())
            .expect("real SNP report verifies against pinned ARK-Milan");
        assert!(res.chain_valid);
        assert!(res.signature_valid);

        let m = res.measurements;
        assert_eq!(
            hex(&m.measurement),
            "5b0ce64ad1c1f6375dbda5f760b98526ca1bcf91b8195091afc28e7b024251d68fe32e05af34048d6607678cd23283ff"
        );
        assert_eq!(
            hex(&m.report_data[..32]),
            "758a38582cd731e63bc3d28d9b890ce82c8214afa0edab1196c5a7c7ff87396b"
        );
        assert_eq!(hex(&m.chip_id[..8]), "7dd2dd89d69087a1");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
