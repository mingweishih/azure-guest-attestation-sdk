// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Standalone SNP ID-block key binding and signature verification.

use super::crypto;
use crate::tee_report::snp::{SnpReport, SNP_REPORT_SIZE};
use std::io;
use x509_parser::der_parser::der::{parse_der_sequence, DerObjectContent};

/// AMD SEV-SNP firmware ABI: ID_BLOCK version 1 (not the report version).
const ID_BLOCK_VERSION: u32 = 1;
const ID_BLOCK_SIZE: usize = 96;
/// AMD SEV-SNP firmware ABI ECDSA_PUBKEY, including reserved bytes.
const ID_PUBLIC_KEY_SIZE: usize = 0x404;
const ID_KEY_CURVE_P384: u32 = 2;
const P384_COORDINATE_SIZE: usize = 48;
const AMD_COORDINATE_SIZE: usize = 72;
const MAX_CERTIFICATE_SIZE: usize = 64 * 1024;

/// Standalone ID-block verification, not SNP report authentication.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SnpIdBlockVerifyResult {
    /// AMD-encoded certificate public key matches the report's ID_KEY_DIGEST.
    pub id_key_digest_valid: bool,
    /// The supplied signature verifies over the reconstructed ID block.
    pub id_block_signature_valid: bool,
    /// SHA-384 of the full AMD ECDSA_PUBKEY encoding, not the certificate DER.
    pub id_key_digest: [u8; 48],
    /// Exact version-1 ID_BLOCK bytes used for signature verification.
    pub id_block_payload: [u8; 96],
}

/// Check a certificate's ID-key binding and signature over an SNP ID block.
///
/// Inputs are an exact 1,184-byte SNP report (version 2 through 5), one PEM
/// X.509 certificate containing an uncompressed named P-384 public key, and a
/// canonical DER ECDSA signature. The signature uses SHA-384 over ID_BLOCK v1:
/// MEASUREMENT, FAMILY_ID, IMAGE_ID, version 1, GUEST_SVN, and POLICY.
///
/// ID_KEY_DIGEST is SHA-384 of AMD's 1,028-byte ECDSA_PUBKEY representation:
/// curve 2, 72-byte little-endian X/Y coordinates, and zero reserved bytes.
///
/// **This does not authenticate the SNP report.** The certificate is only a
/// public-key container: its chain, validity, revocation, and identity are not
/// checked. Neither AUTHOR_KEY_DIGEST nor author-key signatures are checked.
/// Callers must separately authenticate the same report bytes and authorize the
/// expected ID key before treating a successful result as workload approval.
pub fn verify_snp_id_block(
    report_bytes: &[u8],
    certificate_pem: &[u8],
    signature_der: &[u8],
) -> io::Result<SnpIdBlockVerifyResult> {
    if report_bytes.len() != SNP_REPORT_SIZE {
        return Err(invalid("SNP report must be exactly 1184 bytes"));
    }
    let report =
        crate::parse::snp_report(report_bytes).map_err(|_| invalid("invalid SNP report layout"))?;
    if !matches!(report.version, 2..=5) {
        return Err(invalid("unsupported SNP report version"));
    }
    let key_digest = certificate_key_digest(certificate_pem)?;
    if key_digest != report.id_key_digest {
        return Err(invalid(
            "certificate public key does not match SNP ID_KEY_DIGEST",
        ));
    }
    let (signature_r, signature_s) = signature_components(signature_der)?;
    let certificate = crypto::cert_from_pem(certificate_pem.trim_ascii())?;
    let payload = id_block_payload(&report);
    if !crypto::ecdsa_verify_raw(
        &certificate,
        crypto::DigestAlg::Sha384,
        &payload,
        &signature_r,
        &signature_s,
    )? {
        return Err(invalid("SNP ID-block signature verification failed"));
    }
    Ok(SnpIdBlockVerifyResult {
        id_key_digest_valid: true,
        id_block_signature_valid: true,
        id_key_digest: key_digest,
        id_block_payload: payload,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn certificate_key_digest(pem: &[u8]) -> io::Result<[u8; 48]> {
    if pem.len() > MAX_CERTIFICATE_SIZE {
        return Err(invalid("ID-key certificate is too large"));
    }
    let pem = pem.trim_ascii();
    if !pem.starts_with(b"-----BEGIN CERTIFICATE-----") {
        return Err(invalid("expected one PEM X.509 certificate"));
    }
    let (remaining, block) = x509_parser::pem::parse_x509_pem(pem)
        .map_err(|_| invalid("invalid ID-key PEM certificate"))?;
    if !remaining.trim_ascii().is_empty() || block.label != "CERTIFICATE" {
        return Err(invalid(
            "expected exactly one PEM certificate without trailing data",
        ));
    }
    let (remaining, certificate) = x509_parser::parse_x509_certificate(&block.contents)
        .map_err(|_| invalid("invalid ID-key X.509 certificate"))?;
    if !remaining.is_empty() {
        return Err(invalid("trailing ID-key certificate DER bytes"));
    }
    let key = certificate.public_key();
    if key.algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || key
            .algorithm
            .parameters
            .as_ref()
            .filter(|parameters| parameters.tag() == x509_parser::der_parser::ber::Tag::Oid)
            .and_then(|parameters| parameters.as_oid().ok())
            .is_none_or(|oid| oid.to_id_string() != "1.3.132.0.34")
        || key.subject_public_key.unused_bits != 0
    {
        return Err(invalid("ID key must use the named secp384r1 curve"));
    }
    let encoded = amd_public_key(&key.subject_public_key.data)?;
    crypto::sha384(&encoded)?
        .try_into()
        .map_err(|_| invalid("invalid SHA-384 output length"))
}

fn amd_public_key(point: &[u8]) -> io::Result<[u8; ID_PUBLIC_KEY_SIZE]> {
    if point.len() != 1 + 2 * P384_COORDINATE_SIZE || point[0] != 4 {
        return Err(invalid("ID key must be an uncompressed P-384 point"));
    }
    let mut encoded = [0; ID_PUBLIC_KEY_SIZE];
    encoded[..4].copy_from_slice(&ID_KEY_CURVE_P384.to_le_bytes());
    for (coordinate, output) in point[1..].as_chunks::<P384_COORDINATE_SIZE>().0.iter().zip(
        encoded[4..4 + 2 * AMD_COORDINATE_SIZE]
            .as_chunks_mut::<AMD_COORDINATE_SIZE>()
            .0
            .iter_mut(),
    ) {
        for (source, destination) in coordinate.iter().rev().zip(output.iter_mut()) {
            *destination = *source;
        }
    }
    Ok(encoded)
}

fn signature_components(bytes: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
    if !(8..=104).contains(&bytes.len()) {
        return Err(invalid("expected a DER P-384 ECDSA signature"));
    }
    let (remaining, sequence) =
        parse_der_sequence(bytes).map_err(|_| invalid("invalid DER ECDSA signature"))?;
    let values = sequence
        .as_sequence()
        .map_err(|_| invalid("expected ECDSA signature sequence"))?;
    if !remaining.is_empty() || values.len() != 2 {
        return Err(invalid("ECDSA signature must contain exactly two integers"));
    }
    let mut components = [Vec::new(), Vec::new()];
    let mut canonical_body = Vec::new();
    for (value, component) in values.iter().zip(components.iter_mut()) {
        let DerObjectContent::Integer(integer) = &value.content else {
            return Err(invalid("ECDSA signature components must be integers"));
        };
        if integer.is_empty()
            || integer.len() > 49
            || integer[0] & 0x80 != 0
            || (integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
        {
            return Err(invalid("noncanonical ECDSA signature integer"));
        }
        let unsigned = integer.strip_prefix(&[0]).unwrap_or(integer);
        if unsigned.len() > P384_COORDINATE_SIZE || unsigned.iter().all(|byte| *byte == 0) {
            return Err(invalid("invalid P-384 signature component"));
        }
        let length =
            u8::try_from(integer.len()).map_err(|_| invalid("invalid DER integer length"))?;
        canonical_body.extend_from_slice(&[2, length]);
        canonical_body.extend_from_slice(integer);
        *component = unsigned.to_vec();
    }
    let length =
        u8::try_from(canonical_body.len()).map_err(|_| invalid("invalid DER signature length"))?;
    let mut canonical = vec![0x30, length];
    canonical.extend_from_slice(&canonical_body);
    if canonical != bytes {
        return Err(invalid("noncanonical DER ECDSA signature"));
    }
    let [signature_r, signature_s] = components;
    Ok((signature_r, signature_s))
}

fn id_block_payload(report: &SnpReport) -> [u8; ID_BLOCK_SIZE] {
    let mut payload = [0; ID_BLOCK_SIZE];
    payload[..48].copy_from_slice(&report.measurement);
    payload[48..64].copy_from_slice(&report.family.to_le_bytes());
    payload[64..80].copy_from_slice(&report.image_id.to_le_bytes());
    payload[80..84].copy_from_slice(&ID_BLOCK_VERSION.to_le_bytes());
    payload[84..88].copy_from_slice(&report.guest_svn.to_le_bytes());
    payload[88..96].copy_from_slice(&report.policy.to_le_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    const REPORT: &[u8] = include_bytes!("testdata/snp_id_block_report.bin");
    const CERT: &[u8] = include_bytes!("testdata/snp_id_block_cert.pem");
    const SIGNATURE: &[u8] = include_bytes!("testdata/snp_id_block_signature.der");

    #[test]
    fn verifies_independent_id_block_vector_without_authenticating_report() {
        let result = verify_snp_id_block(REPORT, CERT, SIGNATURE).unwrap();
        assert!(result.id_key_digest_valid && result.id_block_signature_valid);
        assert_eq!(hex::encode(result.id_key_digest), "1633528eef911eff2fcd1fb71e669acbcc6465dc213f6f8cb67d809cc8217c7f342dbdaa2f8da4adec47332279e31e3e");
        assert_eq!(hex::encode(result.id_block_payload), "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5001000000785634120000030000000000");
        assert!(REPORT[0x2a0..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn public_key_encoding_has_little_endian_coordinates_and_full_padding() {
        let mut point = [0; 97];
        point[0] = 4;
        for (index, byte) in point[1..].iter_mut().enumerate() {
            *byte = u8::try_from(index + 1).unwrap();
        }
        let key = amd_public_key(&point).unwrap();
        assert_eq!(&key[..4], &[2, 0, 0, 0]);
        assert_eq!(&key[4..52], &(1..=48u8).rev().collect::<Vec<_>>());
        assert!(key[52..76].iter().all(|byte| *byte == 0));
        assert_eq!(&key[76..124], &(49..=96u8).rev().collect::<Vec<_>>());
        assert!(key[124..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn rejects_changed_id_block_fields_digest_and_signature() {
        for offset in [4, 8, 0x10, 0x20, 0x90] {
            let mut report = REPORT.to_vec();
            report[offset] ^= 1;
            let error = verify_snp_id_block(&report, CERT, SIGNATURE).unwrap_err();
            assert!(
                error.to_string().contains("signature"),
                "offset {offset:#x}: {error}"
            );
        }
        let mut report = REPORT.to_vec();
        report[0xe0] ^= 1;
        assert!(verify_snp_id_block(&report, CERT, SIGNATURE)
            .unwrap_err()
            .to_string()
            .contains("ID_KEY_DIGEST"));
        report[0xe0..0x110].fill(0);
        assert!(verify_snp_id_block(&report, CERT, SIGNATURE).is_err());
        let mut signature = SIGNATURE.to_vec();
        *signature.last_mut().unwrap() ^= 1;
        assert!(verify_snp_id_block(REPORT, CERT, &signature).is_err());
    }

    #[test]
    fn certificate_hash_and_spki_hash_are_not_id_key_digests() {
        let (_, pem) = x509_parser::pem::parse_x509_pem(CERT).unwrap();
        let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
        for input in [pem.contents.as_slice(), certificate.public_key().raw] {
            let mut report = REPORT.to_vec();
            report[0xe0..0x110].copy_from_slice(&crypto::sha384(input).unwrap());
            assert!(verify_snp_id_block(&report, CERT, SIGNATURE).is_err());
        }
    }

    #[test]
    fn only_id_block_fields_are_authenticated_by_this_operation() {
        for offset in [0x30, 0x50, 0x110, 0x180, 0x1a0, 0x2a0] {
            let mut report = REPORT.to_vec();
            report[offset] ^= 1;
            verify_snp_id_block(&report, CERT, SIGNATURE).unwrap();
        }
        for version in 2..=5u32 {
            let mut report = REPORT.to_vec();
            report[..4].copy_from_slice(&version.to_le_bytes());
            verify_snp_id_block(&report, CERT, SIGNATURE).unwrap();
        }
    }

    #[test]
    fn rejects_wrong_report_sizes_and_unknown_versions() {
        for length in [0, 16, SNP_REPORT_SIZE - 1] {
            assert!(verify_snp_id_block(&REPORT[..length], CERT, SIGNATURE).is_err());
        }
        let mut report = REPORT.to_vec();
        report.push(0);
        assert!(verify_snp_id_block(&report, CERT, SIGNATURE).is_err());
        report.pop();
        for version in [0u32, 1, 6, u32::MAX] {
            report[..4].copy_from_slice(&version.to_le_bytes());
            assert!(verify_snp_id_block(&report, CERT, SIGNATURE).is_err());
        }
    }

    #[test]
    fn rejects_wrong_key_malformed_certificates_and_multiple_certificates() {
        let chain = include_bytes!("testdata/snp_vcek_chain_genoa.pem");
        let (_, pem) = x509_parser::pem::parse_x509_pem(chain).unwrap();
        let other = pem_text(&pem.contents);
        assert!(verify_snp_id_block(REPORT, &other, SIGNATURE)
            .unwrap_err()
            .to_string()
            .contains("ID_KEY_DIGEST"));
        for certificate in [
            vec![],
            b"not PEM".to_vec(),
            [CERT, CERT].concat(),
            [CERT, b"trailing"].concat(),
            [b"prefix", CERT].concat(),
            vec![0; MAX_CERTIFICATE_SIZE + 1],
        ] {
            assert!(verify_snp_id_block(REPORT, &certificate, SIGNATURE).is_err());
        }
        let (_, mut pem) = x509_parser::pem::parse_x509_pem(CERT).unwrap();
        pem.contents.push(0);
        assert!(verify_snp_id_block(REPORT, &pem_text(&pem.contents), SIGNATURE).is_err());
        assert!(verify_snp_id_block(REPORT, &pem_text(&[0]), SIGNATURE).is_err());
        let with_whitespace = [b"\n ".as_slice(), CERT, b"\n \t"].concat();
        verify_snp_id_block(REPORT, &with_whitespace, SIGNATURE).unwrap();
    }

    fn pem_text(der: &[u8]) -> Vec<u8> {
        use base64::Engine;
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
        .into_bytes()
    }

    #[test]
    fn certificate_is_only_a_public_key_container() {
        let (_, mut pem) = x509_parser::pem::parse_x509_pem(CERT).unwrap();
        *pem.contents.last_mut().unwrap() ^= 1;
        let result = verify_snp_id_block(REPORT, &pem_text(&pem.contents), SIGNATURE).unwrap();
        assert!(result.id_block_signature_valid);
    }

    #[test]
    fn der_signature_rejects_wrong_formats_and_noncanonical_integers() {
        for signature in [
            vec![],
            vec![0; 96],
            vec![0; 512],
            vec![0x30, 6, 2, 1, 0, 2, 1, 1],
            vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
            vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
            vec![0x30, 0x81, 6, 2, 1, 1, 2, 1, 1],
            vec![0x30, 6, 4, 1, 1, 2, 1, 1],
            vec![0x30, 9, 2, 1, 1, 2, 1, 1, 2, 1, 1],
            [SIGNATURE, &[0]].concat(),
            SIGNATURE[..SIGNATURE.len() - 1].to_vec(),
        ] {
            assert!(verify_snp_id_block(REPORT, CERT, &signature).is_err());
        }
        assert_eq!(
            signature_components(&[0x30, 7, 2, 2, 0, 0x80, 2, 1, 1]).unwrap(),
            (vec![0x80], vec![1])
        );
    }

    #[test]
    fn rejects_other_curves_and_compressed_id_keys() {
        assert!(amd_public_key(&[0; 97]).is_err());
        assert!(amd_public_key(&[4; 65]).is_err());
        assert!(amd_public_key(&[2; 49]).is_err());
        let (_, pem) = x509_parser::pem::parse_x509_pem(CERT).unwrap();
        let mut der = pem.contents;
        let oid = &[6, 5, 0x2b, 0x81, 4, 0, 0x22];
        let offset = der
            .windows(oid.len())
            .position(|bytes| bytes == oid)
            .unwrap();
        der[offset + oid.len() - 1] ^= 1;
        assert!(verify_snp_id_block(REPORT, &pem_text(&der), SIGNATURE)
            .unwrap_err()
            .to_string()
            .contains("curve"));
    }

    #[test]
    fn id_block_v1_uses_report_fields_in_abi_order() {
        let mut bytes = *include_bytes!("testdata/snp_report_genoa.bin");
        bytes[0x10..0x20].fill(0x12);
        bytes[0x20..0x30].fill(0x34);
        let report = crate::parse::snp_report(&bytes).unwrap();
        let payload = id_block_payload(&report);
        assert_eq!(payload.len(), 96);
        assert_eq!(&payload[..48], &bytes[0x90..0xc0]);
        assert_eq!(&payload[48..64], &bytes[0x10..0x20]);
        assert_eq!(&payload[64..80], &bytes[0x20..0x30]);
        assert_eq!(&payload[80..84], &[1, 0, 0, 0]);
        assert_eq!(&payload[84..88], &bytes[4..8]);
        assert_eq!(&payload[88..96], &bytes[8..16]);
        assert_ne!(&payload[80..84], &bytes[..4]);
    }
}
