// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `azure-guest-local-verify` — offline verification of Azure CVM attestation
//! evidence (Intel TDX quotes, AMD SEV-SNP reports) against pinned hardware
//! roots, without a round-trip to MAA.
//!
//! Verification is OpenSSL-backed and currently Linux-only.

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        imp::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!(
            "azure-guest-local-verify currently supports Linux only (OpenSSL-backed verification)"
        )
    }
}

#[cfg(target_os = "linux")]
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
        },
    }

    pub fn run() -> Result<()> {
        let cli = Cli::parse();
        let (tee, result) = match &cli.command {
            Command::Tdx { quote } => {
                let bytes =
                    std::fs::read(quote).with_context(|| format!("read {}", quote.display()))?;
                let r = verify::verify_td_quote(&bytes, &verify::TdxVerifyPolicy::default());
                (
                    "tdx",
                    r.map(|_| {
                        vec![
                            ("body signature", true),
                            ("attestation-key binding", true),
                            ("QE report signature", true),
                            ("PCK chain -> Intel SGX Root CA", true),
                        ]
                    }),
                )
            }
            Command::Snp { report, vcek } => {
                let rep =
                    std::fs::read(report).with_context(|| format!("read {}", report.display()))?;
                let chain =
                    std::fs::read(vcek).with_context(|| format!("read {}", vcek.display()))?;
                let r =
                    verify::verify_snp_report(&rep, &chain, &verify::SnpVerifyPolicy::default());
                (
                    "snp",
                    r.map(|_| {
                        vec![
                            ("VCEK chain -> AMD ARK root", true),
                            ("report signature", true),
                        ]
                    }),
                )
            }
        };

        let passed = result.is_ok();
        emit(cli.json, tee, &result);
        if passed {
            Ok(())
        } else {
            exit(2)
        }
    }

    fn emit(json: bool, tee: &str, result: &Result<Vec<(&str, bool)>, std::io::Error>) {
        if json {
            match result {
                Ok(checks) => {
                    let checks_json = checks
                        .iter()
                        .map(|(k, v)| format!("\"{k}\":{v}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    println!("{{\"tee\":\"{tee}\",\"passed\":true,\"checks\":{{{checks_json}}}}}");
                }
                Err(e) => {
                    let msg = e.to_string().replace('\\', "\\\\").replace('"', "\\\"");
                    println!("{{\"tee\":\"{tee}\",\"passed\":false,\"error\":\"{msg}\"}}");
                }
            }
            return;
        }
        match result {
            Ok(checks) => {
                println!("{} verification: PASSED", tee.to_uppercase());
                for (k, _) in checks {
                    println!("  {k}: ok");
                }
            }
            Err(e) => {
                eprintln!("{} verification: FAILED", tee.to_uppercase());
                eprintln!("  reason: {e}");
            }
        }
    }
}
