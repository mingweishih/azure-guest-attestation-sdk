# Windows crypto backend for the offline verifier — requirements

Task for the Windows agent: make the `verify` feature build and pass on
**Windows** using CNG (BCrypt) + CryptoAPI (crypt32), lifting the current
Linux-only restriction. Do **not** change any verification semantics or byte
layouts — only provide a Windows implementation of the crypto primitives.

## 0. Context / where things are

- Feature: `verify = ["native"]` in
  [`crates/azure-guest-attestation-sdk/Cargo.toml`](../../Cargo.toml). `native`
  already selects SChannel+CNG for `reqwest` on Windows.
- Module: `crates/azure-guest-attestation-sdk/src/verify/`
  - `mod.rs` — feature entry; currently has a
    `#[cfg(not(target_os = "linux"))] compile_error!(...)` gate.
  - `crypto.rs` — **the only OpenSSL-dependent file.** All primitives live here.
  - `roots.rs` — pinned trust anchors (parses PEM via `crypto`).
  - `snp.rs`, `tdx.rs` — verification logic; backend-agnostic **except** they
    currently name `openssl::x509::X509` directly.
- `windows-sys 0.61` is already a workspace dep with features
  `Win32_Security_Cryptography` + `Win32_Foundation` enabled (covers BCrypt
  **and** crypt32). Add more `Win32_*` features to the workspace `windows-sys`
  entry in the root `Cargo.toml` if you need them.

## 1. Goal / acceptance criteria

On **both** Linux and Windows, with `--no-default-features --features verify`:

```
cargo build   -p azure-guest-attestation-sdk --no-default-features --features verify
cargo clippy  -p azure-guest-attestation-sdk --no-default-features --features verify --all-targets -- -D warnings
cargo test    -p azure-guest-attestation-sdk --no-default-features --features verify
cargo build   -p azure-guest-local-verify
```

The **four real-evidence tests must pass on Windows** (they validate real
fixtures against the pinned roots — these are the ground truth):

- `verify::tdx::tests::verifies_real_tdx_quote_end_to_end` (QGS-wrapped)
- `verify::tdx::tests::verifies_real_raw_tdx_quote` (raw / non-wrapped)
- `verify::snp::tests::verifies_real_turin_report` (P-384, ARK-Turin)
- `verify::snp::tests::verifies_real_milan_report` (P-384, ARK-Milan)

Linux behavior must be **unchanged** (all 14 verify tests still green on Linux).

## 2. Step 1 — make the interface backend-neutral (touches Linux code)

`crypto.rs` leaks `openssl::x509::X509` into `snp.rs`/`tdx.rs` (the
`*_with_roots` signatures take `&[X509]`, and `snp.rs` calls
`c.issued(c) != X509VerifyResult::OK`). Introduce a backend-neutral certificate
handle so neither `snp.rs` nor `tdx.rs` names OpenSSL or Windows types:

- Add `pub(crate) struct Cert(...)` in `crypto.rs` — on Linux wraps
  `openssl::x509::X509`; on Windows wraps an owned DER blob and/or a
  `CERT_CONTEXT`.
- Add `pub(crate) fn cert_is_self_signed(&Cert) -> bool` and use it in
  `snp.rs` instead of `issued(...)`.
- Change `roots.rs` to return `Vec<Cert>` / `Cert`, and the `*_with_roots`
  signatures in `snp.rs`/`tdx.rs` to take `&[Cert]`.

Do this refactor first with **only the Linux (OpenSSL) impl** and confirm the 14
tests stay green. This isolates the Windows work to a second impl of the same
interface.

## 3. Step 2 — the `crypto` interface to implement for Windows

Provide `#[cfg(windows)]` implementations with identical signatures and
semantics. Callers already handle all byte-order conversions (see §4), so these
must behave byte-for-byte like the OpenSSL versions:

| Function | Semantics |
|----------|-----------|
| `sha256(&[u8]) -> io::Result<Vec<u8>>` | SHA-256 digest. BCrypt `BCryptHashData` with `BCRYPT_SHA256_ALGORITHM`. |
| `parse_pem_chain(&[u8]) -> io::Result<Vec<Cert>>` | Split concatenated PEM → DER (`CryptStringToBinaryA` / `CRYPT_STRING_BASE64HEADER`), then `CertCreateCertificateContext`. Preserve order (leaf first). |
| `cert_from_pem(&[u8]) -> io::Result<Cert>` | Single-cert parse (used by `roots.rs`). |
| `cert_is_self_signed(&Cert) -> bool` | Subject == issuer AND self-signature verifies. |
| `ecdsa_verify_raw(cert, digest_alg, msg, r_be, s_be) -> io::Result<bool>` | Verify ECDSA over `msg` under the cert's EC public key. Curve (P-256/P-384) is taken from the cert. `digest_alg` is SHA-256 or SHA-384. |
| `ecdsa_p256_verify_point(x_y_64, msg, r_be, s_be) -> io::Result<bool>` | Same, but the public key is a bare uncompressed `x‖y` point (64 bytes, big-endian), SHA-256. |
| `verify_cert_chain(leaf, intermediates, roots) -> io::Result<()>` | Validate `leaf` chains via `intermediates` to **one of** `roots`, and to **nothing else** (roots are pinned — do not fall back to the machine trust store). |

### CNG signature-format notes (critical)

- `BCryptVerifySignature` expects the raw signature as `r ‖ s`, each **fixed
  size, big-endian**: 32 bytes for P-256, **48 bytes for P-384**. The callers
  pass `r_be`/`s_be` already big-endian, but for SNP they originate from
  72-byte little-endian fields and are only reversed, so they may be 72 bytes
  or short. **Left-pad/trim `r_be`/`s_be` to the curve size** before calling
  CNG. (OpenSSL's `BigNum` tolerates arbitrary lengths; CNG does not.)
- Import the EC public key as `BCRYPT_ECCPUBLIC_BLOB`: header
  (`BCRYPT_ECDSA_P256`/`P384` magic + key length) followed by `X ‖ Y`
  big-endian. For `ecdsa_p256_verify_point`, `x_y_64` is already `X‖Y`; for
  `ecdsa_verify_raw`, extract `X‖Y` from the cert's `SubjectPublicKeyInfo`
  (crypt32 `CryptImportPublicKeyInfoEx2` gives a CNG key handle directly — the
  simplest path).

### Chain validation with pinned roots

- Build an in-memory `HCERTSTORE`, add the pinned root(s), and use
  `CertGetCertificateChain` with a chain engine that trusts **only** that
  store, or verify each link manually (issuer signature + basic constraints)
  and require the terminal cert to byte-equal a pinned root. Either way: the
  chain must fail if it does not terminate at a pinned root. Ignore time
  validity mismatches only if the Linux path does (it currently uses OpenSSL
  defaults — keep parity; do not add CRL/OCSP here, that is a separate task).

## 4. Byte-order facts (already handled by callers — do NOT change)

These are encoded in `snp.rs`/`tdx.rs` and verified against real hardware
evidence. The Windows crypto layer must not re-order anything.

- **SNP**: ECDSA **P-384** / SHA-384. `r`,`s` each a 72-byte **little-endian**
  field; signed data = `report[0..0x2A0]`.
- **TDX**: ECDSA **P-256** / SHA-256. `r`,`s` 32-byte **big-endian**.
  Attestation pubkey is a bare **big-endian** `x‖y` (64 B). Body signature
  covers header+body (632 B for v4). QE report signature (by PCK) is over the
  384-byte QE report. Binding: `qe_report[320..352] == SHA256(att_pubkey(64) ‖
  qe_auth_data)`. PCK chain roots at the pinned Intel SGX Root CA.

## 5. Cargo / feature wiring

- On Windows, `verify` needs the CNG/crypt32 APIs. `windows-sys` is already a
  `cfg(windows)` dependency; ensure the `verify` feature pulls in whatever it
  needs. Since `windows-sys` is **not** optional today, no new `dep:` is
  required — just add any missing `Win32_*` sub-features to the workspace
  `windows-sys` entry (root `Cargo.toml`).
- `openssl` stays a `cfg(target_os = "linux")`-only optional dep. Never let
  `verify` pull OpenSSL on Windows.
- MSRV is **1.90**; `windows-sys 0.61` must keep compiling on it.

## 6. mod.rs gate + CI

- In `mod.rs`, narrow the gate so it only rejects platforms that are neither
  Linux nor Windows:
  ```rust
  #[cfg(not(any(target_os = "linux", target_os = "windows")))]
  compile_error!("the `verify` feature requires Linux (OpenSSL) or Windows (CNG/crypt32)");
  ```
- CI: the `verify` job in [`.github/workflows/ci.yml`](../../../../.github/workflows/ci.yml)
  is currently `ubuntu-latest` only. Add a `windows-latest` leg (matrix) running
  the same clippy/test/build commands from §1.

## 7. Tests: which run where

- The **four real-evidence tests** (§1) are backend-agnostic → must pass on
  Windows.
- The **synthetic** tests in `crypto.rs` (`roundtrip`) and `snp.rs`
  (`synthetic_case`, tamper/untrusted-root) generate keys/certs **with
  OpenSSL**. Either (a) reimplement their setup behind a small test helper that
  has a Windows variant, or (b) gate the OpenSSL-only setup with
  `#[cfg(target_os = "linux")]` and add equivalent Windows-side negative tests
  (tampered signature, untrusted root) using CNG-generated keys. Prefer (a) if
  cheap; (b) is acceptable. Do not delete negative-path coverage.

## 8. Out of scope (separate follow-ups — do not do here)

- TCB-status (fmspc/TCB-info) evaluation and CRL/OCSP revocation.
- SNP VCEK↔report extension binding (HWID/TCB OIDs).
- Event-log ↔ quote/report binding.
