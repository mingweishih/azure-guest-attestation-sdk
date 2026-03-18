// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub mod snp;
pub mod td_quote;
pub mod tdx;
pub mod vbs;

pub use td_quote::{
    parse_td_quote, parse_td_quote_with_options, pretty_td_quote as pretty_td_quote_v5,
    ParsedTdQuote, TdQuoteBody, TdQuoteParseError, TdQuoteSignatureMode,
};

use std::fmt::Write as _;

/// Render a byte slice as grouped hex (no 0x prefix), 32 bytes per line indented.
fn fmt_hex_block(out: &mut String, label: &str, bytes: &[u8]) {
    let _ = writeln!(out, "{label} ({} bytes):", bytes.len());
    for chunk in bytes.chunks(32) {
        let _ = write!(out, "    ");
        for b in chunk {
            let _ = write!(out, "{b:02x}");
        }
        let _ = writeln!(out);
    }
}

/// Pretty print an SNP report.
pub fn pretty_snp(report: &snp::SnpReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "SNP Report:");
    let _ = writeln!(out, "  version: {}", report.version);
    let _ = writeln!(out, "  guest_svn: {}", report.guest_svn);
    let _ = writeln!(out, "  policy: 0x{:016x}", report.policy);
    let _ = writeln!(out, "  vmpl: {}", report.vmpl);
    let _ = writeln!(out, "  signature_algo: {}", report.signature_algo);
    let _ = writeln!(out, "  current_tcb: 0x{:016x}", report.current_tcb);
    let _ = writeln!(out, "  platform_info: 0x{:016x}", report.platform_info);
    let _ = writeln!(out, "  flags: 0x{:08x}", report.flags);
    fmt_hex_block(&mut out, "  family", &report.family.to_le_bytes());
    fmt_hex_block(&mut out, "  image_id", &report.image_id.to_le_bytes());
    fmt_hex_block(&mut out, "  report_data", &report.report_data);
    fmt_hex_block(&mut out, "  measurement", &report.measurement);
    fmt_hex_block(&mut out, "  host_data", &report.host_data);
    fmt_hex_block(&mut out, "  id_key_digest", &report.id_key_digest);
    fmt_hex_block(&mut out, "  author_key_digest", &report.author_key_digest);
    fmt_hex_block(&mut out, "  report_id", &report.report_id);
    fmt_hex_block(&mut out, "  report_id_ma", &report.report_id_ma);
    let _ = writeln!(out, "  reported_tcb: 0x{:016x}", report.reported_tcb);
    fmt_hex_block(&mut out, "  chip_id", &report.chip_id);
    let _ = writeln!(out, "  committed_tcb: 0x{:016x}", report.committed_tcb);
    let _ = writeln!(
        out,
        "  current version: {}.{}.{}",
        report.current_major, report.current_minor, report.current_build
    );
    let _ = writeln!(
        out,
        "  committed version: {}.{}.{}",
        report.committed_major, report.committed_minor, report.committed_build
    );
    let _ = writeln!(out, "  launch_tcb: 0x{:016x}", report.launch_tcb);
    fmt_hex_block(&mut out, "  signature", &report.signature);
    out
}

/// Pretty print a TDX report.
pub fn pretty_tdx(report: &tdx::TdReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "TDX Report:");
    let mac = &report.report_mac_struct;
    let _ = writeln!(
        out,
        "  report_type.tee_type: 0x{:02x}",
        mac.report_type.tee_type
    );
    let _ = writeln!(
        out,
        "  report_type.sub_type: 0x{:02x}",
        mac.report_type.sub_type
    );
    let _ = writeln!(out, "  report_type.version: {}", mac.report_type.version);
    fmt_hex_block(&mut out, "  tee_tcb_info_hash", &mac.tee_tcb_info_hash);
    fmt_hex_block(&mut out, "  tee_info_hash", &mac.tee_info_hash);
    fmt_hex_block(&mut out, "  report_data", &mac.report_data);
    fmt_hex_block(&mut out, "  mac", &mac.mac);
    let tcb = &report.tee_tcb_info;
    fmt_hex_block(&mut out, "  tee_tcb_info.valid", &tcb.valid);
    fmt_hex_block(&mut out, "  tee_tcb_info.mr_seam", &tcb.mr_seam);
    fmt_hex_block(&mut out, "  tee_tcb_info.attributes", &tcb.attributes);
    let tdinfo = &report.td_info.td_info_base;
    fmt_hex_block(&mut out, "  mr_td", &tdinfo.mr_td);
    fmt_hex_block(&mut out, "  mr_config_id", &tdinfo.mr_config_id);
    fmt_hex_block(&mut out, "  mr_owner", &tdinfo.mr_owner);
    fmt_hex_block(&mut out, "  mr_owner_config", &tdinfo.mr_owner_config);
    for (i, r) in tdinfo.rtmr.iter().enumerate() {
        fmt_hex_block(&mut out, &format!("  rtmr[{i}]"), r);
    }
    fmt_hex_block(&mut out, "  servd_hash", &tdinfo.servd_hash);
    out
}

/// Pretty print a VBS report.
pub fn pretty_vbs(report: &vbs::VbsReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "VBS Report:");
    let _ = writeln!(out, "  version: {}", report.version);
    fmt_hex_block(&mut out, "  report_data", &report.report_data);
    fmt_hex_block(&mut out, "  identity.owner_id", &report.identity.owner_id);
    fmt_hex_block(
        &mut out,
        "  identity.measurement",
        &report.identity.measurement,
    );
    fmt_hex_block(&mut out, "  identity.signer", &report.identity.signer);
    fmt_hex_block(&mut out, "  identity.host_data", &report.identity.host_data);
    let _ = writeln!(out, "  identity.guest_svn: {}", report.identity.guest_svn);
    fmt_hex_block(&mut out, "  signature", &report.signature);
    out
}
