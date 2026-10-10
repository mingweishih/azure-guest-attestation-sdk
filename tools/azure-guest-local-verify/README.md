# Azure Guest Local Verify

Offline verification of Intel TDX quotes and AMD SEV-SNP reports against
pinned hardware roots. Supported on Linux (OpenSSL) and Windows (CNG/crypt32).

## TDX

`azure-guest-local-verify tdx QUOTE` retains upstream's signature and PCK-chain
verification for bare and QGS-wrapped quotes. It does not appraise Intel TCB
Info, QE identity, revocation, or migration policy.

## SNP

`azure-guest-local-verify snp REPORT --vcek CHAIN` now requires supported SNP
report structure, chain/signature validity, and VCEK role/product/TCB/HWID
bindings. JSON adds `checks["VCEK report binding"]` and
`verification_scope: "structure_signature_chain_and_vcek_binding"`.

`passed: true` does **not** mean acceptance policy or revocation passed:
`policy_checked`, `crl_checked`, and `cpuid_stepping_checked` are false.
Acceptance policy remains the caller's responsibility. See the
[SNP verification design](../../doc/snp-verification.md) for binding rules,
compatibility, and unchecked policy details.

Add `--json` for machine-readable output. SNP verification returns exit 0 on
success and 2 on invalid evidence, mismatched collateral, or input-read failure.
SNP failures use fixed `error` messages and `error_code` categories; raw
certificate/parser error contents and paths are not printed.

Optionally verify the report's ID block in the same command:

```bash
azure-guest-local-verify snp report.bin --vcek vcek-chain.pem \
	--id-block-certificate id-key.pem \
	--id-block-signature id-block-signature.der --json
```

The ID certificate and signature options must be supplied together. The command
first verifies the VCEK report and bindings, then checks the ID-key digest and
ID-block signature against the same in-memory report bytes. Both stages must
pass; missing, malformed, or mismatched optional inputs never fall back to
report-only success.

Combined output uses scope
`structure_signature_chain_and_vcek_binding_and_id_block` and reports
`report_signature_checked` and `id_block_checked`. If the ID-block stage fails
after successful report verification, the first flag remains true but `passed`
is false. `certificate_trust_checked: false` refers to the ID-key certificate,
not the verified VCEK chain: the ID certificate remains only a key container.
Author-key checks, ID-key authorization, general policy and revocation remain
outside scope. Omitting both options preserves ordinary `snp` behavior.

## SNP ID Block

```bash
azure-guest-local-verify snp-id-block report.bin \
	--certificate id-key.pem --signature id-block-signature.der --json
```

Checks the certificate's P-384 ID key against report `ID_KEY_DIGEST` and
verifies a DER ECDSA-P384/SHA384 signature over ID_BLOCK v1 reconstructed from
the report. The certificate must contain one PEM X.509 certificate.

This standalone command does **not** authenticate the report, trust the
certificate, check its expiry/revocation, or authorize the ID key. JSON uses
`verification_scope: "id_key_digest_and_id_block_signature"` and explicitly
reports those unchecked trust boundaries. Exit 0 means only these two checks
passed; invalid inputs or failed checks return exit 2. See the
[ID-block design](../../doc/snp-id-block.md) for wire formats and composition
with full report verification.

## Validation

Run `cargo fmt -p azure-guest-local-verify -- --check`,
`cargo test -p azure-guest-local-verify`, and
`cargo clippy -p azure-guest-local-verify --all-targets -- -D warnings`.