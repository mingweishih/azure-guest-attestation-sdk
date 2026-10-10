// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `azure-guest-local-verify` — offline verification of Azure CVM attestation
//! evidence (Intel TDX quotes, AMD SEV-SNP reports) against pinned hardware
//! roots, without a round-trip to MAA.
//!
//! Verification uses the platform crypto backend: OpenSSL on Linux, CNG +
//! crypt32 on Windows.

fn main() -> anyhow::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        imp::run()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        anyhow::bail!("azure-guest-local-verify supports Linux and Windows only")
    }
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
mod imp {
    use anyhow::{Context, Result};
    use azure_guest_attestation_sdk::verify;
    use clap::{Parser, Subcommand};
    use std::path::PathBuf;
    use std::process::exit;

    #[derive(Parser)]
    #[command(
        name = "azure-guest-local-verify",
        about = "Local (offline) verification of Azure CVM attestation evidence"
    )]
    struct Cli {
        #[command(subcommand)]
        command: Command,
        /// Emit a machine-readable JSON result.
        #[arg(long, global = true)]
        json: bool,
    }

    #[derive(Subcommand)]
    enum Command {
        /// Verify an Intel TDX quote (bare or QGS-wrapped) to the pinned Intel
        /// SGX Root CA.
        Tdx {
            /// Path to the TDX quote file.
            quote: PathBuf,
        },
        /// Verify an AMD SEV-SNP report against its VCEK certificate chain
        /// (validated to a pinned AMD ARK root).
        Snp {
            /// Path to the raw SNP attestation report (0x4a0 bytes).
            report: PathBuf,
            /// Path to the VCEK certificate chain (PEM: VCEK, ASK[, ARK]).
            #[arg(long)]
            vcek: PathBuf,
            /// PEM X.509 ID-key certificate; requires --id-block-signature.
            #[arg(long, requires = "id_block_signature")]
            id_block_certificate: Option<PathBuf>,
            /// DER ID-block signature; requires --id-block-certificate.
            #[arg(long, requires = "id_block_certificate")]
            id_block_signature: Option<PathBuf>,
        },
        /// Check ID_KEY_DIGEST and an ID-block v1 signature, not the report's authenticity.
        SnpIdBlock {
            /// Raw SNP report containing the ID-block fields.
            report: PathBuf,
            /// One PEM X.509 certificate containing the P-384 ID public key.
            #[arg(long)]
            certificate: PathBuf,
            /// DER-encoded ECDSA-P384/SHA384 signature over the ID-block payload.
            #[arg(long)]
            signature: PathBuf,
        },
    }

    /// A successful verification: the checks performed and the verified fields.
    struct Report {
        checks: Vec<(&'static str, bool)>,
        fields: Vec<(&'static str, String)>,
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn run() -> Result<()> {
        let cli = Cli::parse();
        let mut report_signature_checked = false;
        let (tee, result): (&str, Result<Report, std::io::Error>) =
            match &cli.command {
                Command::Tdx { quote } => {
                    let bytes = std::fs::read(quote)
                        .with_context(|| format!("read {}", quote.display()))?;
                    let r = verify::verify_td_quote(&bytes, &verify::TdxVerifyPolicy::default())
                        .map(|r| Report {
                            checks: vec![
                                ("body signature", r.quote_signature_valid),
                                ("attestation-key binding", r.attestation_key_bound),
                                ("QE report signature", r.qe_report_signature_valid),
                                ("PCK chain -> Intel SGX Root CA", r.pck_chain_valid),
                            ],
                            fields: vec![
                                ("mr_td", hex(&r.measurements.mr_td)),
                                ("mr_seam", hex(&r.measurements.mr_seam)),
                                ("rtmr0", hex(&r.measurements.rtmr[0])),
                                ("rtmr1", hex(&r.measurements.rtmr[1])),
                                ("rtmr2", hex(&r.measurements.rtmr[2])),
                                ("rtmr3", hex(&r.measurements.rtmr[3])),
                                ("report_data", hex(&r.measurements.report_data)),
                                ("tee_tcb_svn", hex(&r.measurements.tee_tcb_svn)),
                                ("td_attributes", hex(&r.measurements.td_attributes)),
                                ("xfam", hex(&r.measurements.xfam)),
                            ],
                        });
                    ("tdx", r)
                }
                Command::Snp {
                    report,
                    vcek,
                    id_block_certificate,
                    id_block_signature,
                } => {
                    let result = (|| {
                        let rep = std::fs::read(report)?;
                        let chain = std::fs::read(vcek)?;
                        let verified = verify::verify_snp_report(
                            &rep,
                            &chain,
                            &verify::SnpVerifyPolicy::default(),
                        )?;
                        report_signature_checked = true;
                        let mut output = Report {
                            checks: vec![
                                ("VCEK chain -> AMD ARK root", verified.chain_valid),
                                ("report signature", verified.signature_valid),
                                ("VCEK report binding", verified.vcek_binding_valid),
                            ],
                            fields: vec![
                                ("measurement", hex(&verified.measurements.measurement)),
                                ("report_data", hex(&verified.measurements.report_data)),
                                (
                                    "reported_tcb",
                                    format!("{:016x}", verified.measurements.reported_tcb),
                                ),
                                ("chip_id", hex(&verified.measurements.chip_id)),
                            ],
                        };
                        match (id_block_certificate, id_block_signature) {
                            (Some(certificate), Some(signature)) => {
                                add_id_block_checks(&mut output, &rep, certificate, signature)?;
                            }
                            (None, None) => {}
                            _ => {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidInput,
                                    "both ID-block certificate and signature are required",
                                ))
                            }
                        }
                        Ok(output)
                    })();
                    (
                        if id_block_certificate.is_some() {
                            "snp-with-id-block"
                        } else {
                            "snp"
                        },
                        result,
                    )
                }
                Command::SnpIdBlock {
                    report,
                    certificate,
                    signature,
                } => {
                    let result = (|| {
                        let report = read_id_block_input(report, 1184)?;
                        let mut output = Report {
                            checks: Vec::new(),
                            fields: Vec::new(),
                        };
                        add_id_block_checks(&mut output, &report, certificate, signature)?;
                        Ok(output)
                    })();
                    ("snp-id-block", result)
                }
            };

        let passed = result.is_ok();
        emit(cli.json, tee, &result, report_signature_checked);
        if passed {
            Ok(())
        } else {
            exit(2)
        }
    }

    fn add_id_block_checks(
        output: &mut Report,
        report: &[u8],
        certificate: &std::path::Path,
        signature: &std::path::Path,
    ) -> std::io::Result<()> {
        let certificate = read_id_block_input(certificate, 64 * 1024)?;
        let signature = read_id_block_input(signature, 104)?;
        let result = verify::verify_snp_id_block(report, &certificate, &signature)?;
        output.checks.extend([
            ("ID key digest binding", result.id_key_digest_valid),
            ("ID-block signature", result.id_block_signature_valid),
        ]);
        output.fields.extend([
            ("id_key_digest", hex(&result.id_key_digest)),
            ("id_block_payload", hex(&result.id_block_payload)),
        ]);
        Ok(())
    }

    fn read_id_block_input(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ID-block input exceeds size limit",
            ));
        }
        Ok(bytes)
    }

    fn emit(
        json: bool,
        tee: &str,
        result: &Result<Report, std::io::Error>,
        report_signature_checked: bool,
    ) {
        let id_block = tee == "snp-id-block";
        let combined = tee == "snp-with-id-block";
        let snp = tee == "snp" || id_block || combined;
        if json && snp {
            let mut output = serde_json::json!({
                "tee": "snp", "passed": result.is_ok(),
                "verification_scope": if id_block { "id_key_digest_and_id_block_signature" } else if combined { "structure_signature_chain_and_vcek_binding_and_id_block" } else { "structure_signature_chain_and_vcek_binding" },
                "policy_checked": false, "crl_checked": false, "cpuid_stepping_checked": false,
            });
            if id_block || combined {
                output["report_signature_checked"] = serde_json::json!(report_signature_checked);
                output["id_block_checked"] = serde_json::json!(result.is_ok());
                output["certificate_trust_checked"] = serde_json::json!(false);
                output["author_key_checked"] = serde_json::json!(false);
                output["id_block_version"] = serde_json::json!(1);
            }
            match result {
                Ok(report) => {
                    output["checks"] = serde_json::Value::Object(
                        report
                            .checks
                            .iter()
                            .map(|(key, value)| ((*key).into(), serde_json::json!(value)))
                            .collect(),
                    );
                    output["measurements"] = serde_json::Value::Object(
                        report
                            .fields
                            .iter()
                            .map(|(key, value)| ((*key).into(), serde_json::json!(value)))
                            .collect(),
                    );
                }
                Err(error) => {
                    let (code, message) = snp_error(error);
                    output["error_code"] = serde_json::json!(code);
                    output["error"] = serde_json::json!(message);
                }
            }
            println!("{output}");
            return;
        }
        if json {
            match result {
                Ok(rep) => {
                    let checks = rep
                        .checks
                        .iter()
                        .map(|(k, v)| format!("\"{k}\":{v}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    let fields = rep
                        .fields
                        .iter()
                        .map(|(k, v)| format!("\"{k}\":\"{v}\""))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!(
                        "{{\"tee\":\"{tee}\",\"passed\":true,\"checks\":{{{checks}}},\"measurements\":{{{fields}}}}}"
                    );
                }
                Err(e) => {
                    let msg = e.to_string().replace('\\', "\\\\").replace('"', "\\\"");
                    println!("{{\"tee\":\"{tee}\",\"passed\":false,\"error\":\"{msg}\"}}");
                }
            }
            return;
        }
        if tee == "snp" {
            println!("  verification_scope: structure_signature_chain_and_vcek_binding");
            println!("  policy_checked: false; CRL and CPUID stepping equivalence: not checked");
            println!("  REPORTDATA, measurement, TCB minimums and migration authorization require caller policy.");
        }
        if combined {
            println!(
                "  verification_scope: structure_signature_chain_and_vcek_binding_and_id_block"
            );
            println!(
                "  report_signature_checked: {report_signature_checked}; id_block_checked: {}",
                result.is_ok()
            );
            println!("  ID certificate trust, author key, policy and revocation: not checked");
        }
        if id_block {
            println!("  verification_scope: id_key_digest_and_id_block_signature");
            println!("  id_block_version: 1");
            println!("  report_signature_checked: false; certificate_trust_checked: false; author_key_checked: false");
            println!("  Standalone key/signature check only. Authenticate the SNP report and authorize the ID key separately.");
        }
        match result {
            Ok(rep) => {
                println!("{} verification: PASSED", tee.to_uppercase());
                for (k, _) in &rep.checks {
                    println!("  {k}: ok");
                }
                println!("measurements:");
                for (k, v) in &rep.fields {
                    println!("  {k}: {v}");
                }
            }
            Err(e) => {
                eprintln!("{} verification: FAILED", tee.to_uppercase());
                if snp {
                    eprintln!("  reason: {}", snp_error(e).1);
                } else {
                    eprintln!("  reason: {e}");
                }
            }
        }
    }

    fn snp_error(error: &std::io::Error) -> (&'static str, &'static str) {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::NotFound => ("input_not_found", "An input file was not found"),
            ErrorKind::PermissionDenied => (
                "permission_denied",
                "Permission denied while reading an input",
            ),
            ErrorKind::InvalidInput => ("invalid_input", "Invalid verification input or time"),
            ErrorKind::InvalidData => (
                "invalid_evidence",
                "Invalid, expired, or mismatched evidence or collateral",
            ),
            _ => (
                "verification_failed",
                "Signature, certificate-chain, or verification-time validation failed",
            ),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn id_block_checks_append_without_replacing_existing_results() {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../crates/azure-guest-attestation-sdk/src/verify/testdata");
            let report = std::fs::read(root.join("snp_id_block_report.bin")).unwrap();
            let mut output = Report {
                checks: vec![("existing check", true)],
                fields: vec![("existing field", "unchanged".into())],
            };
            add_id_block_checks(
                &mut output,
                &report,
                &root.join("snp_id_block_cert.pem"),
                &root.join("snp_id_block_signature.der"),
            )
            .unwrap();
            assert_eq!(
                output.checks,
                vec![
                    ("existing check", true),
                    ("ID key digest binding", true),
                    ("ID-block signature", true)
                ]
            );
            assert_eq!(output.fields[0], ("existing field", "unchanged".into()));
            assert_eq!(output.fields[1].0, "id_key_digest");
            assert_eq!(output.fields[2].0, "id_block_payload");
            let original_checks = output.checks.clone();
            let original_fields = output.fields.clone();
            let mut tampered = report;
            tampered[0x90] ^= 1;
            assert!(add_id_block_checks(
                &mut output,
                &tampered,
                &root.join("snp_id_block_cert.pem"),
                &root.join("snp_id_block_signature.der")
            )
            .is_err());
            assert_eq!(output.checks, original_checks);
            assert_eq!(output.fields, original_fields);
        }
    }
}
