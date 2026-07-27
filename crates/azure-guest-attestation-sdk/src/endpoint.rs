// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Microsoft Azure Attestation (MAA) regional endpoint selection.
//!
//! Azure exposes a shared MAA instance in most regions at a well-known URL.
//! This module maps an Azure region name (as reported by IMDS) to the base
//! URL of the shared MAA endpoint for that region, so callers can attest
//! without hard-coding an endpoint.
//!
//! The returned value is a **base URL** (e.g.
//! `https://sharedeus.eus.attest.azure.net`). The attestation path and
//! api-version (`/attest/AzureGuest`, `/attest/SevSnpVm`, `/attest/TdxVm`)
//! are appended automatically by the provider/submission layer.
//!
//! # Example
//!
//! Resolve from an explicit region name (offline, no network):
//!
//! ```
//! use azure_guest_attestation_sdk::endpoint;
//!
//! let base = endpoint::maa_base_url_for_region("eastus");
//! assert_eq!(base.as_deref(), Some("https://sharedeus.eus.attest.azure.net"));
//! ```
//!
//! Or auto-detect from the current VM's region via IMDS (requires network):
//!
//! ```no_run
//! use azure_guest_attestation_sdk::endpoint;
//!
//! # fn main() -> std::io::Result<()> {
//! let base = endpoint::detect_maa_base_url()?;
//! println!("MAA base URL: {base}");
//! # Ok(())
//! # }
//! ```

use std::io;

/// Default commercial-cloud MAA base URL, used when a region cannot be matched.
///
/// MAA shared regional endpoints are interchangeable for guest attestation,
/// so an unmatched region falls back to this stable default rather than
/// failing.
pub const DEFAULT_COMMERCIAL_BASE_URL: &str = "https://sharedeus.eus.attest.azure.net";

/// Default US Government-cloud MAA base URL, used when a `usgov*` region
/// cannot be matched exactly.
pub const DEFAULT_USGOV_BASE_URL: &str = "https://sharedugv.ugv.attest.azure.us";

/// Region → shared MAA base URL for the Azure commercial cloud.
///
/// Keys are normalized (lowercase, no spaces).
const COMMERCIAL_ENDPOINTS: &[(&str, &str)] = &[
    ("australiacentral", "https://sharedcau.cau.attest.azure.net"),
    (
        "australiacentral2",
        "https://sharedcau2.cau2.attest.azure.net",
    ),
    ("australiaeast", "https://sharedeau.eau.attest.azure.net"),
    (
        "australiasoutheast",
        "https://sharedsau.sau.attest.azure.net",
    ),
    ("austriaeast", "https://sharedate.ate.attest.azure.net"),
    ("brazilsouth", "https://sharedsbr.sbr.attest.azure.net"),
    (
        "brazilsoutheast",
        "https://sharedsebr.sebr.attest.azure.net",
    ),
    ("canadacentral", "https://sharedcac.cac.attest.azure.net"),
    ("canadaeast", "https://sharedcae.cae.attest.azure.net"),
    ("centralindia", "https://sharedcin.cin.attest.azure.net"),
    ("centralus", "https://sharedcus.cus.attest.azure.net"),
    ("centraluseuap", "https://sharedcuse.cuse.attest.azure.net"),
    ("chilecentral", "https://sharedclc.clc.attest.azure.net"),
    ("eastasia", "https://sharedeasia.easia.attest.azure.net"),
    ("eastus", "https://sharedeus.eus.attest.azure.net"),
    ("eastus2", "https://sharedeus2.eus2.attest.azure.net"),
    ("eastus2euap", "https://sharedeus2e.eus2e.attest.azure.net"),
    ("francecentral", "https://sharedfrc.frc.attest.azure.net"),
    ("francesouth", "https://sharedfrs.frs.attest.azure.net"),
    ("germanynorth", "https://sharedden.den.attest.azure.net"),
    (
        "germanywestcentral",
        "https://shareddewc.dewc.attest.azure.net",
    ),
    ("israelcentral", "https://sharedilc.ilc.attest.azure.net"),
    ("italynorth", "https://shareditn.itn.attest.azure.net"),
    ("japaneast", "https://sharedjpe.jpe.attest.azure.net"),
    ("japanwest", "https://sharedjpw.jpw.attest.azure.net"),
    (
        "jioindiacentral",
        "https://sharedjinc.jinc.attest.azure.net",
    ),
    ("jioindiawest", "https://sharedjinw.jinw.attest.azure.net"),
    ("koreacentral", "https://sharedkrc.krc.attest.azure.net"),
    ("koreasouth", "https://sharedkrs.krs.attest.azure.net"),
    ("malaysiasouth", "https://sharedmys.mys.attest.azure.net"),
    ("mexicocentral", "https://sharedmxc.mxc.attest.azure.net"),
    ("newzealandnorth", "https://sharednzn.nzn.attest.azure.net"),
    ("northcentralus", "https://sharedncus.ncus.attest.azure.net"),
    ("northeurope", "https://sharedneu.neu.attest.azure.net"),
    ("norwayeast", "https://sharednoe.noe.attest.azure.net"),
    ("norwaywest", "https://sharednow.now.attest.azure.net"),
    ("polandcentral", "https://sharedplc.plc.attest.azure.net"),
    ("southafricanorth", "https://sharedsan.san.attest.azure.net"),
    ("southafricawest", "https://sharedsaw.saw.attest.azure.net"),
    ("southcentralus", "https://sharedscus.scus.attest.azure.net"),
    ("southindia", "https://sharedsin.sin.attest.azure.net"),
    (
        "southeastasia",
        "https://sharedsasia.sasia.attest.azure.net",
    ),
    ("spaincentral", "https://sharedesc.esc.attest.azure.net"),
    ("swedencentral", "https://sharedsec.sec.attest.azure.net"),
    ("swedensouth", "https://sharedses.ses.attest.azure.net"),
    ("switzerlandnorth", "https://sharedswn.swn.attest.azure.net"),
    ("switzerlandwest", "https://sharedsww.sww.attest.azure.net"),
    ("taiwannorth", "https://sharedtwn.twn.attest.azure.net"),
    (
        "taiwannorthwest",
        "https://sharedtwnw.twnw.attest.azure.net",
    ),
    ("uaecentral", "https://shareduaec.uaec.attest.azure.net"),
    ("uaenorth", "https://shareduaen.uaen.attest.azure.net"),
    ("uksouth", "https://shareduks.uks.attest.azure.net"),
    ("ukwest", "https://sharedukw.ukw.attest.azure.net"),
    ("westcentralus", "https://sharedwcus.wcus.attest.azure.net"),
    ("westeurope", "https://sharedweu.weu.attest.azure.net"),
    ("westindia", "https://sharedwin.win.attest.azure.net"),
    ("westus", "https://sharedwus.wus.attest.azure.net"),
    ("westus2", "https://sharedwus2.wus2.attest.azure.net"),
    ("westus3", "https://sharedwus3.wus3.attest.azure.net"),
];

/// Region → shared MAA base URL for the Azure US Government cloud.
///
/// Keys are normalized (lowercase, no spaces).
const USGOV_ENDPOINTS: &[(&str, &str)] = &[
    ("usgovvirginia", "https://sharedugv.ugv.attest.azure.us"),
    ("usgovarizona", "https://shareduga.uga.attest.azure.us"),
    ("usgovtexas", "https://shareduga.uga.attest.azure.us"),
];

/// Normalize a region name to the table's key format: lowercase, no spaces.
fn normalize_region(region: &str) -> String {
    region
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Resolve an Azure region name to the shared MAA base URL for that region.
///
/// Returns `None` when the region is not present in the built-in tables.
/// Matching is case-insensitive and ignores spaces (so both `"East US"` and
/// `"eastus"`, or `"USGov Virginia"` and `"usgovvirginia"`, resolve).
///
/// Use [`maa_base_url_for_region_or_default`] to fall back to a stable
/// default endpoint instead of `None`.
pub fn maa_base_url_for_region(region: &str) -> Option<&'static str> {
    let key = normalize_region(region);
    COMMERCIAL_ENDPOINTS
        .iter()
        .chain(USGOV_ENDPOINTS.iter())
        .find(|(k, _)| *k == key)
        .map(|(_, url)| *url)
}

/// Resolve an Azure region name to a shared MAA base URL, falling back to a
/// stable default when the region is unknown.
///
/// Unknown `usgov*` regions fall back to [`DEFAULT_USGOV_BASE_URL`]; all other
/// unknown regions fall back to [`DEFAULT_COMMERCIAL_BASE_URL`]. MAA shared
/// regional endpoints are interchangeable for guest attestation, so this
/// fallback preserves functionality rather than failing on new/unlisted
/// regions.
pub fn maa_base_url_for_region_or_default(region: &str) -> String {
    if let Some(url) = maa_base_url_for_region(region) {
        return url.to_string();
    }
    let key = normalize_region(region);
    if key.starts_with("usgov") {
        DEFAULT_USGOV_BASE_URL.to_string()
    } else {
        DEFAULT_COMMERCIAL_BASE_URL.to_string()
    }
}

/// Detect the current VM's region via IMDS and resolve the shared MAA base URL.
///
/// This queries the Azure Instance Metadata Service for the VM's region
/// (`compute/location`) and maps it to a shared MAA base URL using
/// [`maa_base_url_for_region_or_default`]. Requires the IMDS endpoint to be
/// reachable (i.e. running on an Azure VM).
pub fn detect_maa_base_url() -> io::Result<String> {
    let region = crate::guest_attest::ImdsClient::new().get_region()?;
    Ok(maa_base_url_for_region_or_default(&region))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_commercial_region() {
        assert_eq!(
            maa_base_url_for_region("eastus"),
            Some("https://sharedeus.eus.attest.azure.net")
        );
        assert_eq!(
            maa_base_url_for_region("westeurope"),
            Some("https://sharedweu.weu.attest.azure.net")
        );
    }

    #[test]
    fn resolves_case_and_space_insensitively() {
        assert_eq!(
            maa_base_url_for_region("East US"),
            Some("https://sharedeus.eus.attest.azure.net")
        );
        assert_eq!(
            maa_base_url_for_region("USGov Virginia"),
            Some("https://sharedugv.ugv.attest.azure.us")
        );
    }

    #[test]
    fn unknown_region_falls_back_to_default() {
        assert_eq!(
            maa_base_url_for_region_or_default("atlantis"),
            DEFAULT_COMMERCIAL_BASE_URL
        );
    }

    #[test]
    fn unknown_usgov_region_falls_back_to_usgov_default() {
        assert_eq!(
            maa_base_url_for_region_or_default("USGov Nowhere"),
            DEFAULT_USGOV_BASE_URL
        );
    }

    #[test]
    fn known_region_or_default_matches_table() {
        assert_eq!(
            maa_base_url_for_region_or_default("westus3"),
            "https://sharedwus3.wus3.attest.azure.net"
        );
    }
}
