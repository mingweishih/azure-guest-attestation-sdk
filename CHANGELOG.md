# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Local (offline) attestation verification** behind a new `verify` feature
  (requires the `native` backend; Linux/OpenSSL for now, Windows CNG+crypt32
  pending).
  - `verify::verify_snp_report()` validates an AMD SEV-SNP report's VCEK chain
    to a **pinned AMD ARK root** (Milan, Genoa) and verifies the report
    signature (ECDSA P-384 / SHA-384).
  - `verify::verify_td_quote()` validates an Intel TDX ECDSA quote end to end:
    the body signature (ECDSA P-256), the attestation-key binding to the QE
    report (`report_data`), the QE report signature (PCK), and the PCK
    certificate chain to a **pinned Intel SGX Root CA**. QGS `GET_QUOTE_RESP`
    envelopes (TDX QGS / MigTD) are unwrapped transparently.
- **`azure-guest-local-verify` CLI** — a new tool that verifies attestation
  evidence offline: `tdx <quote>` and `snp <report> --vcek <chain.pem>`, with
  text or `--json` output and exit code 2 on failure. Linux-only (OpenSSL).

### Changed

- **CLI `--json` `tcb` is derived from the MAA claims for SEV-SNP.** MAA reports
  only the granular SNP SVNs, so the CLI now renders the 8-byte AMD `TCB_VERSION`
  as big-endian hex (e.g. `DB18000000000004`) composed from
  `x-ms-sevsnpvm-{bootloader,tee,snpfw,microcode}-svn` instead of leaving `tcb`
  `null`. This matches the TCB string historically emitted by cvm-attestation-tools
  and used by ACC-VM-Tests as a grouping key. TDX continues to use
  `tdx_tee_tcb_svn`. Works at the top level and nested under `x-ms-isolation-tee`.

- **`azure-guest-attest` CLI 0.2.0 — pluggable crypto backend.** The CLI can now
  be built against platform crypto instead of the pure-Rust `ring`/`aes`/`sha1`
  crates (a compliance requirement). A new `native` feature routes TLS through
  `native-tls` (OpenSSL on Linux, SChannel on Windows) and AES-GCM / SHA-1
  through OpenSSL (Linux) / CNG-BCrypt (Windows). The shipped release binary is
  built with `--no-default-features --features native` and contains none of
  `ring`, `aes`, or `sha1`.
  - **Breaking (packaging):** the `native` Linux binary is **dynamically linked**
    against the system OpenSSL — the fully-static musl artifact is no longer
    produced. The Linux release asset moves from `x86_64-unknown-linux-musl` to
    `x86_64-unknown-linux-gnu` and requires `libssl`/`libcrypto` on the host.
    Windows uses the OS-provided SChannel/CNG (no extra runtime dependency).

### Added

- **Feature-gated crypto backends** in `azure-tpm` and
  `azure-guest-attestation-sdk`: `rustcrypto` (default, portable, pure-Rust,
  published to crates.io) and `native` (platform crypto). The published crates
  keep the pure-Rust default so downstream consumers are unaffected.

### Removed

- Unused `sha1` and `digest` dependencies from `azure-guest-attestation-sdk`,
  and the unused `reqwest` dependency and static-CRT `build.rs` from the CLI.

## [0.1.0] - 2026-03-18

Initial release. `azure-tpm` and `azure-guest-attestation-sdk` are publishable
to crates.io; the reference-TPM test harness (`ms-tpm-20-ref`) is pulled only
for tests via cfg-gated dev-dependencies and the non-published
`azure-tpm-testkit` crate, activated with `--cfg vtpm_tests`.

Minimum Supported Rust Version (MSRV): **1.90**.

### Added

- **High-level `AttestationClient` API** — one-shot `attest()` and decomposed
  `get_cvm_evidence()` → `get_device_evidence()` → `create_attestation_report()`
  → `submit_to_provider()` workflow.
- **`Tpm::from_raw_reference` / `Tpm::is_reference`** on `azure-tpm`, enabling
  non-hardware (reference/simulator) transports.
- **TEE-only attestation** via `attest_platform()` / `submit_tee_only()`.
- **TrustedLaunch VM support** — auto-detected when CVM report NV index is
  absent. `IsolationInfo` carries `vm_type: TrustedLaunch` with no TEE evidence.
- **TPM 2.0 command layer** — `CreatePrimary`, `Load`, `EvictControl`, `Sign`,
  `VerifySignature`, `Quote`, `Certify`, `PCR_Read`, `PolicyPCR`, `NV_Read`,
  `NV_Write`, `NV_DefineSpace`, `RSA_Decrypt`, and ECDSA P-256 signing.
- **TEE report parsers** — Intel TDX (TDREPORT + TD Quote v4/v5), AMD SEV-SNP,
  VBS report structures.
- **Stateless `parse` module** — offline inspection of SNP reports, TDX reports,
  TD Quotes, and JWT attestation tokens.
- **MAA provider** — Microsoft Azure Attestation integration with retry +
  exponential backoff.
- **TCG event log** collection (Linux `binary_bios_measurements`, Windows WBCL).
- **Token decryption** — AES-256-GCM envelope decryption using ephemeral TPM key.
- **Cross-platform** — Linux (`/dev/tpmrm0`) and Windows (TBS) TPM access.
- **CLI tool** (`azure-guest-attest`) for diagnostics, testing, and reference usage.

[Unreleased]: https://github.com/Azure/azure-guest-attestation-sdk/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Azure/azure-guest-attestation-sdk/releases/tag/v0.1.0
