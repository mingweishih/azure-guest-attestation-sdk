# SNP ID-Block Verification

[Design index](README.md) | [SNP report verification](snp-verification.md) |
[CLI usage](../tools/azure-guest-local-verify/README.md#snp-id-block)

## Contract

`verify::verify_snp_id_block(report, certificate_pem, signature_der)` performs
two standalone checks:

1. The certificate's AMD-encoded ID public key hashes to `ID_KEY_DIGEST` in
   the supplied report.
2. That key verifies the supplied ECDSA-P384/SHA384 signature over the
   version-1 ID-block payload reconstructed from the report.

Inputs are an exact 1,184-byte report (versions 2 through 5), one PEM X.509
certificate with an uncompressed named P-384 public key, and a canonical DER
ECDSA signature. AMD's padded 512-byte signature structure and raw `r || s`
signatures are not accepted by this interface. Trailing certificate/signature
data, multiple certificates, wrong key types, and malformed encodings fail.

## Key Digest Encoding

`ID_KEY_DIGEST` is SHA-384 over AMD's complete `ECDSA_PUBKEY` structure,
including reserved bytes. It is not a digest of the certificate, SPKI, or just
the EC point.

| Offset | Size | Content |
|---|---|---|
| `0x000` | 4 | Curve ID 2, little-endian (P-384) |
| `0x004` | 72 | X coordinate, little-endian and zero-padded |
| `0x04c` | 72 | Y coordinate, little-endian and zero-padded |
| `0x094` | 880 | Zero reserved bytes |

The hashed structure is 1,028 bytes. Coordinates are extracted from the
certificate's uncompressed EC public point, not from certificate metadata.
Two certificates carrying the same public key therefore produce the same
ID-key digest regardless of subject, issuer, dates, or certificate signature.

## Payload Reconstruction

The 96-byte payload is serialized explicitly, without native struct padding:

| Offset | Size | ID_BLOCK field | Source |
|---|---|---|---|
| `0x00` | 48 | LD | Report `measurement` |
| `0x30` | 16 | FAMILY_ID | Report `family` |
| `0x40` | 16 | IMAGE_ID | Report `image_id` |
| `0x50` | 4 | VERSION | Fixed little-endian 1 |
| `0x54` | 4 | GUEST_SVN | Report `guest_svn`, little-endian |
| `0x58` | 8 | POLICY | Report `policy`, little-endian |

The ID-block version is not the attestation report version. The report does
not supply an ID-block version, so this API supports only version 1. The
signature covers these exact bytes with SHA-384, without another wrapper or
prehash supplied by the caller. Canonical DER integers are converted to raw
big-endian components for the shared native verification interface.

## Trust Boundary

This API deliberately does **not** verify the SNP report's VCEK signature,
certificate chain, or report-format policy beyond the supported size/version.
The supplied certificate is only a public-key container: certificate identity,
signature, validity dates, trust chain, and revocation are not evaluated.
Author-key signatures and `AUTHOR_KEY_DIGEST` are also outside this operation.

A successful result proves consistency of the ID key and the reconstructed
ID-block fields. It does not prove that hardware produced the supplied report,
that the ID key is authorized, or that this is fresh evidence. Changes to
REPORTDATA, chip ID, platform TCB, and other fields outside the ID block do not
invalidate its signature. Callers needing attestation must separately verify
the **same immutable report bytes**, then apply their expected ID-key and
workload policy.

`SnpIdBlockVerifyResult` returns `id_key_digest_valid`,
`id_block_signature_valid`, the calculated `id_key_digest`, and the exact
`id_block_payload`. Errors do not return a partial success result.

The CLI names its scope `id_key_digest_and_id_block_signature` and always
reports `report_signature_checked: false`, `certificate_trust_checked: false`,
and `author_key_checked: false`, including on failure. `passed` is scoped to
the two ID-block checks, not full attestation approval.

## Combined Report Verification

The `snp` CLI accepts paired `--id-block-certificate` and
`--id-block-signature` options in addition to its required `--vcek` input.
It invokes full SNP report verification first, including VCEK binding, and
then invokes `verify_snp_id_block` using the same report byte buffer. The file
is not reopened between stages. An ID-block failure is fatal when requested;
there is no fallback to report-only acceptance.

The combined scope is
`structure_signature_chain_and_vcek_binding_and_id_block`. Successful output
contains both report and ID-block check sets and measurements. On failure,
`passed` is false and `id_block_checked` is false. `report_signature_checked`
is true only if the report-verification stage completed successfully, including
when a subsequent ID-block input or verification fails. The ID certificate's
trust and author-key checks remain unchecked; this is distinct from the VCEK
chain validation performed by the report stage.

Without these options, `snp` retains its existing contract. The standalone
`snp-id-block` subcommand is still available and never authenticates the report.

## Implementation and Tests

- [ID-block verifier and tests](../crates/azure-guest-attestation-sdk/src/verify/snp_id_block.rs)
- [Native crypto interface](../crates/azure-guest-attestation-sdk/src/verify/crypto/mod.rs)
- [CLI regression tests](../tools/azure-guest-local-verify/tests/snp_cli.rs)

Public synthetic fixtures exercise the same signature and digest on Linux and
Windows. Their report has no valid VCEK signature, explicitly testing the
standalone boundary. Tests cover exact wire encodings, independent expected
digest/payload values, each ID-block field, key/digest mismatch, DER
canonicality, wrong curves, input sizes, and CLI scope/error output.

Wire-format references: AMD SEV-SNP Firmware ABI structures `ID_BLOCK` and
`ECDSA_PUBKEY`. The encoding is also implemented by
[virtee/sev ID-block types](https://github.com/virtee/sev/blob/main/src/measurement/idblock_types.rs)
and its [key-digest calculation](https://github.com/virtee/sev/blob/main/src/measurement/idblock.rs).