// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(any(target_os = "linux", target_os = "windows"))]

use std::{path::PathBuf, process::Command};

const PLATFORMS: [&str; 3] = ["milan", "genoa", "turin"];

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/azure-guest-attestation-sdk/src/verify/testdata")
        .join(name)
}

fn id_block_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"));
    command
        .args(["--json", "snp-id-block"])
        .arg(fixture("snp_id_block_report.bin"))
        .arg("--certificate")
        .arg(fixture("snp_id_block_cert.pem"));
    command
}

#[test]
fn id_block_cli_reports_only_standalone_checks() {
    let output = id_block_command()
        .arg("--signature")
        .arg(fixture("snp_id_block_signature.der"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["passed"], true);
    assert_eq!(
        json["verification_scope"],
        "id_key_digest_and_id_block_signature"
    );
    assert_eq!(json["id_block_version"], 1);
    assert_eq!(json["checks"]["ID key digest binding"], true);
    assert_eq!(json["checks"]["ID-block signature"], true);
    assert_eq!(
        json["measurements"]["id_block_payload"]
            .as_str()
            .unwrap()
            .len(),
        192
    );
    for check in [
        "report_signature_checked",
        "certificate_trust_checked",
        "author_key_checked",
        "policy_checked",
        "crl_checked",
    ] {
        assert_eq!(json[check], false, "{check}");
    }
}

#[test]
fn id_block_cli_rejects_missing_and_wrong_signature_inputs() {
    let output = id_block_command().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    for (name, code) in [
        ("missing-id-block-signature-sentinel.der", "input_not_found"),
        ("snp_id_block_report.bin", "invalid_evidence"),
    ] {
        let output = id_block_command()
            .arg("--signature")
            .arg(fixture(name))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["passed"], false);
        assert_eq!(json["error_code"], code);
        assert_eq!(json["report_signature_checked"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("sentinel"));
    }
}

#[test]
fn id_block_cli_human_output_discloses_unchecked_report() {
    let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
        .arg("snp-id-block")
        .arg(fixture("snp_id_block_report.bin"))
        .arg("--certificate")
        .arg(fixture("snp_id_block_cert.pem"))
        .arg("--signature")
        .arg(fixture("snp_id_block_signature.der"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("report_signature_checked: false"));
    assert!(text.contains("certificate_trust_checked: false"));
}

#[test]
fn snp_optional_id_block_requires_both_inputs() {
    for option in ["--id-block-certificate", "--id-block-signature"] {
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
            .args(["--json", "snp"])
            .arg(fixture("snp_report_genoa.bin"))
            .arg("--vcek")
            .arg(fixture("snp_vcek_chain_genoa.pem"))
            .args([option, "unused"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("required"), "{error}");
        assert!(!error.contains("unexpected argument"), "{error}");
    }
}

#[test]
fn snp_combined_id_block_never_bypasses_report_authentication() {
    let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
        .args(["--json", "snp"])
        .arg(fixture("snp_id_block_report.bin"))
        .arg("--vcek")
        .arg(fixture("snp_vcek_chain_genoa.pem"))
        .arg("--id-block-certificate")
        .arg(fixture("snp_id_block_cert.pem"))
        .arg("--id-block-signature")
        .arg(fixture("snp_id_block_signature.der"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["passed"], false);
    assert_eq!(
        json["verification_scope"],
        "structure_signature_chain_and_vcek_binding_and_id_block"
    );
    assert_eq!(json["id_block_checked"], false);
    assert_eq!(json["report_signature_checked"], false);
    assert!(json.get("checks").is_none());
}

#[test]
fn snp_combined_rejects_id_block_failure_after_valid_report() {
    for platform in PLATFORMS {
        for missing_certificate in [false, true] {
            let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
                .args(["--json", "snp"])
                .arg(fixture(&format!("snp_report_{platform}.bin")))
                .arg("--vcek")
                .arg(fixture(&format!("snp_vcek_chain_{platform}.pem")))
                .arg("--id-block-certificate")
                .arg(fixture(if missing_certificate {
                    "missing-id-key-sentinel.pem"
                } else {
                    "snp_id_block_cert.pem"
                }))
                .arg("--id-block-signature")
                .arg(fixture("snp_id_block_signature.der"))
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(2), "{platform}");
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["passed"], false);
            assert_eq!(json["report_signature_checked"], true);
            assert_eq!(json["id_block_checked"], false);
            assert_eq!(json["certificate_trust_checked"], false);
            assert_eq!(
                json["error_code"],
                if missing_certificate {
                    "input_not_found"
                } else {
                    "invalid_evidence"
                }
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("sentinel"));
            assert!(json.get("checks").is_none());
        }
    }
}

#[test]
fn snp_cli_reports_binding_and_unchecked_policy_scope() {
    for generation in PLATFORMS {
        let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
            .args(["--json", "snp"])
            .arg(fixture(&format!("snp_report_{generation}.bin")))
            .arg("--vcek")
            .arg(fixture(&format!("snp_vcek_chain_{generation}.pem")))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["passed"], true);
        assert_eq!(json["checks"]["VCEK report binding"], true);
        assert_eq!(
            json["verification_scope"],
            "structure_signature_chain_and_vcek_binding"
        );
        assert_eq!(json["policy_checked"], false);
        assert_eq!(json["crl_checked"], false);
        assert_eq!(json["cpuid_stepping_checked"], false);
        assert!(json["checks"].get("ID-block signature").is_none());
    }
}

#[test]
fn snp_cli_read_errors_are_scoped_and_redacted() {
    let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
        .args(["--json", "snp"])
        .arg(fixture("missing-report-error-context-sentinel.bin"))
        .arg("--vcek")
        .arg(fixture(&format!("snp_vcek_chain_{}.pem", PLATFORMS[0])))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["passed"], false);
    assert_eq!(json["error_code"], "input_not_found");
    assert_eq!(
        json["verification_scope"],
        "structure_signature_chain_and_vcek_binding"
    );
    assert_eq!(json["policy_checked"], false);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("error-context-sentinel"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("error-context-sentinel"));
}

#[test]
fn snp_cli_rejects_a_mismatched_chain() {
    for report in PLATFORMS {
        for chain in PLATFORMS {
            if report == chain {
                continue;
            }
            let output = Command::new(env!("CARGO_BIN_EXE_azure-guest-local-verify"))
                .args(["--json", "snp"])
                .arg(fixture(&format!("snp_report_{report}.bin")))
                .arg("--vcek")
                .arg(fixture(&format!("snp_vcek_chain_{chain}.pem")))
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(2),
                "{report} report with {chain} chain"
            );
            let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(json["passed"], false);
            assert_eq!(json["policy_checked"], false);
            assert!(json.get("checks").is_none());
        }
    }
}
