// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! TDX endorsement retrieval from Azure Trusted Hardware Identity Management (THIM).
//!
//! The THIM service at `https://{region}.thim.azure.net` provides endorsement
//! data for Intel TDX trust domains.  This module exposes a blocking HTTP
//! client (`ThimClient`) that wraps the following REST endpoints:
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/endorsement/tdx/mrtds` | List known MRTD hex values |
//! | GET | `/endorsement/tdx/{mrtd}` | Fetch endorsement (COSE/CoRIM) for a specific MRTD |
//!
//! # Example
//!
//! ```no_run
//! use azure_guest_attestation_sdk::endorsement::ThimClient;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ThimClient::new("westus");
//!
//! // List all endorsed MRTDs
//! let mrtds = client.list_mrtds()?;
//! for m in &mrtds {
//!     println!("{m}");
//! }
//!
//! // Fetch endorsement for the first MRTD
//! if let Some(first) = mrtds.first() {
//!     let endorsement = client.get_endorsement(first)?;
//!     println!("endorsement: {} bytes", endorsement.data.len());
//! }
//! # Ok(())
//! # }
//! ```

use reqwest::blocking::Client;
use std::io;

/// Default Azure region for the THIM endpoint.
pub const DEFAULT_REGION: &str = "westus";

/// Response from the `/endorsement/tdx/mrtds` endpoint.
#[derive(Debug, Clone, serde::Deserialize)]
struct MrtdListResponse {
    mrtds: Vec<String>,
}

/// Result of [`ThimClient::get_endorsement`] or
/// [`ThimClient::get_endorsement_for_report`].
#[derive(Debug, Clone)]
pub struct EndorsementResponse {
    /// The MRTD (hex, uppercase) this endorsement belongs to.
    pub mrtd: String,
    /// Raw endorsement payload (COSE / CoRIM binary).
    pub data: Vec<u8>,
    /// Content-Type header returned by THIM (typically `application/cose`).
    pub content_type: String,
}

impl EndorsementResponse {
    /// Extract the JSON payload from the COSE_Sign1 envelope.
    ///
    /// Returns the parsed JSON value, or an error if the data is not a valid
    /// COSE_Sign1 structure or the payload is not valid JSON.
    pub fn payload_json(&self) -> io::Result<serde_json::Value> {
        let bytes = parse_cose_sign1_payload(&self.data)?;
        serde_json::from_slice(&bytes)
            .map_err(|e| io::Error::other(format!("payload is not valid JSON: {e}")))
    }
}

/// Extract the payload bytes from a COSE_Sign1 binary.
///
/// A COSE_Sign1 structure (RFC 9052 §4.2) is:
/// ```text
/// COSE_Sign1 = #6.18([       ; CBOR tag 18
///     protected   : bstr,    ; serialised Headers
///     unprotected : map,     ; Headers
///     payload     : bstr,    ; content
///     signature   : bstr,    ; signature
/// ])
/// ```
///
/// This function performs minimal CBOR parsing — just enough to skip to the
/// third element (payload) and return its bytes.  No signature verification
/// is performed.
pub fn parse_cose_sign1_payload(data: &[u8]) -> io::Result<Vec<u8>> {
    let err = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());

    if data.len() < 4 {
        return Err(err("data too short for COSE_Sign1"));
    }

    // Expect CBOR tag 18 (0xd2) followed by array(4) (0x84)
    if data[0] != 0xd2 {
        return Err(err(&format!(
            "expected CBOR tag 18 (0xd2), got 0x{:02x}",
            data[0]
        )));
    }
    if data[1] != 0x84 {
        return Err(err(&format!(
            "expected CBOR array(4) (0x84), got 0x{:02x}",
            data[1]
        )));
    }

    let mut pos: usize = 2;

    // Skip element 0: protected headers (bstr)
    pos = skip_cbor_item(data, pos).map_err(|e| err(&e))?;

    // Skip element 1: unprotected headers (map)
    pos = skip_cbor_item(data, pos).map_err(|e| err(&e))?;

    // Element 2: payload (bstr) — this is what we want
    let (payload, _) = read_cbor_bstr(data, pos).map_err(|e| err(&e))?;

    Ok(payload.to_vec())
}

// ---- Minimal CBOR helpers (just enough for COSE_Sign1 extraction) ----------

/// Read the CBOR "head" (major type + argument) at `pos`.  Returns
/// `(major_type, argument_value, new_pos)`.
fn read_cbor_head(data: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= data.len() {
        return Err("unexpected end of CBOR data".into());
    }
    let initial = data[pos];
    let major = initial >> 5;
    let addl = initial & 0x1f;
    let mut p = pos + 1;

    let value = match addl {
        0..=23 => u64::from(addl),
        24 => {
            if p >= data.len() {
                return Err("truncated CBOR 1-byte length".into());
            }
            let v = u64::from(data[p]);
            p += 1;
            v
        }
        25 => {
            if p + 2 > data.len() {
                return Err("truncated CBOR 2-byte length".into());
            }
            let v = u64::from(u16::from_be_bytes([data[p], data[p + 1]]));
            p += 2;
            v
        }
        26 => {
            if p + 4 > data.len() {
                return Err("truncated CBOR 4-byte length".into());
            }
            let v = u64::from(u32::from_be_bytes([
                data[p],
                data[p + 1],
                data[p + 2],
                data[p + 3],
            ]));
            p += 4;
            v
        }
        27 => {
            if p + 8 > data.len() {
                return Err("truncated CBOR 8-byte length".into());
            }
            let v = u64::from_be_bytes([
                data[p],
                data[p + 1],
                data[p + 2],
                data[p + 3],
                data[p + 4],
                data[p + 5],
                data[p + 6],
                data[p + 7],
            ]);
            p += 8;
            v
        }
        _ => return Err(format!("unsupported CBOR additional info {addl}")),
    };

    Ok((major, value, p))
}

/// Read a CBOR byte-string (major type 2) or text-string (major type 3) at
/// `pos`.  Returns `(slice, new_pos)`.
fn read_cbor_bstr(data: &[u8], pos: usize) -> Result<(&[u8], usize), String> {
    let (major, len, p) = read_cbor_head(data, pos)?;
    if major != 2 && major != 3 {
        return Err(format!(
            "expected bstr/tstr (major 2/3) at offset {pos}, got major {major}"
        ));
    }
    let len = len as usize;
    let end = p.checked_add(len).ok_or("CBOR length overflow")?;
    if end > data.len() {
        return Err(format!(
            "CBOR bstr at offset {pos}: need {len} bytes but only {} remain",
            data.len() - p
        ));
    }
    Ok((&data[p..end], end))
}

/// Skip one complete CBOR item at `pos`, returning the position after it.
fn skip_cbor_item(data: &[u8], pos: usize) -> Result<usize, String> {
    let (major, value, p) = read_cbor_head(data, pos)?;
    match major {
        0 | 1 => Ok(p), // unsigned / negative int
        2 | 3 => {
            // bstr / tstr
            let len = value as usize;
            let end = p.checked_add(len).ok_or("CBOR length overflow")?;
            if end > data.len() {
                return Err(format!("truncated CBOR bstr/tstr at offset {pos}"));
            }
            Ok(end)
        }
        4 => {
            // array
            let count = value as usize;
            let mut cur = p;
            for _ in 0..count {
                cur = skip_cbor_item(data, cur)?;
            }
            Ok(cur)
        }
        5 => {
            // map
            let count = value as usize;
            let mut cur = p;
            for _ in 0..count {
                cur = skip_cbor_item(data, cur)?; // key
                cur = skip_cbor_item(data, cur)?; // value
            }
            Ok(cur)
        }
        6 => skip_cbor_item(data, p), // tag — skip the wrapped item
        7 => Ok(p),                   // simple values / float
        _ => Err(format!("unknown CBOR major type {major}")),
    }
}
///
/// Create with [`ThimClient::new`] (uses [`DEFAULT_REGION`]) or
/// [`ThimClient::with_base_url`] for a custom endpoint.
pub struct ThimClient {
    http: Client,
    base_url: String,
}

impl ThimClient {
    /// Create a client targeting `https://{region}.thim.azure.net`.
    pub fn new(region: &str) -> Self {
        Self {
            http: Client::new(),
            base_url: format!("https://{region}.thim.azure.net"),
        }
    }

    /// Create a client with a fully custom base URL (no trailing slash).
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
        }
    }

    /// List all known TDX MRTDs from THIM.
    ///
    /// Returns uppercase hex strings (96 chars = SHA-384).
    pub fn list_mrtds(&self) -> io::Result<Vec<String>> {
        let url = format!("{}/endorsement/tdx/mrtds", self.base_url);
        tracing::debug!(url = %url, "fetching MRTD list");

        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .map_err(|e| io::Error::other(format!("THIM request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "THIM returned HTTP {status} for {url}"
            )));
        }

        let body: MrtdListResponse = resp
            .json()
            .map_err(|e| io::Error::other(format!("failed to parse MRTD list JSON: {e}")))?;

        tracing::info!(count = body.mrtds.len(), "retrieved MRTD list");
        Ok(body.mrtds)
    }

    /// Fetch endorsement data for a specific MRTD.
    ///
    /// `mrtd_hex` should be the uppercase hex representation of the SHA-384
    /// measurement (96 characters).  The returned [`EndorsementResponse`]
    /// contains the raw COSE/CoRIM binary.
    pub fn get_endorsement(&self, mrtd_hex: &str) -> io::Result<EndorsementResponse> {
        let url = format!("{}/endorsement/tdx/{}", self.base_url, mrtd_hex);
        tracing::debug!(url = %url, "fetching TDX endorsement");

        let resp = self
            .http
            .get(&url)
            .send()
            .map_err(|e| io::Error::other(format!("THIM request failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "THIM returned HTTP {status} for MRTD {mrtd_hex}"
            )));
        }

        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let data = resp
            .bytes()
            .map_err(|e| io::Error::other(format!("failed to read endorsement body: {e}")))?
            .to_vec();

        tracing::info!(
            mrtd = %mrtd_hex,
            content_type = %content_type,
            size = data.len(),
            "retrieved TDX endorsement"
        );

        Ok(EndorsementResponse {
            mrtd: mrtd_hex.to_uppercase(),
            data,
            content_type,
        })
    }

    /// Extract the MRTD from a raw TDX report and fetch its endorsement.
    ///
    /// The `td_report_bytes` must be at least
    /// [`TDX_REPORT_SIZE`](crate::tee_report::tdx::TDX_REPORT_SIZE) bytes.
    /// The `mr_td` field (SHA-384, 48 bytes) is read from the parsed
    /// [`TdReport`](crate::tee_report::tdx::TdReport) and converted to
    /// uppercase hex for the THIM lookup.
    pub fn get_endorsement_for_report(
        &self,
        td_report_bytes: &[u8],
    ) -> io::Result<EndorsementResponse> {
        let report = crate::parse::tdx_report(td_report_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("failed to parse TDX report: {e}"),
            )
        })?;

        let mr_td = &report.td_info.td_info_base.mr_td;
        let mrtd_hex = hex::encode_upper(mr_td);
        tracing::info!(mr_td = %mrtd_hex, "extracted MRTD from TD report");

        self.get_endorsement(&mrtd_hex)
    }
}

impl Default for ThimClient {
    fn default() -> Self {
        Self::new(DEFAULT_REGION)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_westus() {
        let c = ThimClient::default();
        assert_eq!(c.base_url, "https://westus.thim.azure.net");
    }

    #[test]
    fn new_builds_url_from_region() {
        let c = ThimClient::new("eastus");
        assert_eq!(c.base_url, "https://eastus.thim.azure.net");
    }

    #[test]
    fn with_base_url_trims_trailing_slash() {
        let c = ThimClient::with_base_url("https://custom.example.com/");
        assert_eq!(c.base_url, "https://custom.example.com");
    }

    #[test]
    fn endorsement_response_clone() {
        let r = EndorsementResponse {
            mrtd: "AABB".into(),
            data: vec![1, 2, 3],
            content_type: "application/cose".into(),
        };
        let r2 = r.clone();
        assert_eq!(r2.mrtd, "AABB");
        assert_eq!(r2.data, vec![1, 2, 3]);
    }

    #[test]
    fn extract_mrtd_from_report_too_short() {
        let c = ThimClient::default();
        let result = c.get_endorsement_for_report(&[0u8; 10]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("too small") || msg.contains("parse"), "{msg}");
    }

    #[test]
    fn parse_cose_sign1_too_short() {
        assert!(parse_cose_sign1_payload(&[]).is_err());
        assert!(parse_cose_sign1_payload(&[0xd2]).is_err());
        assert!(parse_cose_sign1_payload(&[0xd2, 0x84]).is_err());
    }

    #[test]
    fn parse_cose_sign1_wrong_tag() {
        let err = parse_cose_sign1_payload(&[0xd3, 0x84, 0x40, 0xa0, 0x40, 0x40]).unwrap_err();
        assert!(err.to_string().contains("0xd3"), "{err}");
    }

    #[test]
    fn parse_cose_sign1_wrong_array_len() {
        let err = parse_cose_sign1_payload(&[0xd2, 0x83, 0x40, 0xa0, 0x40]).unwrap_err();
        assert!(err.to_string().contains("0x83"), "{err}");
    }

    #[test]
    fn parse_cose_sign1_valid() {
        // Build a minimal COSE_Sign1: tag(18) array(4)
        //   bstr(3) "abc"    -- protected headers
        //   map(0)           -- unprotected headers
        //   bstr(13) JSON    -- payload
        //   bstr(2) "xx"     -- signature
        let payload_json = br#"{"hello":"ok"}"#;
        let mut buf = Vec::new();
        buf.push(0xd2); // tag(18)
        buf.push(0x84); // array(4)
                        // protected: bstr(3)
        buf.push(0x43);
        buf.extend_from_slice(b"abc");
        // unprotected: map(0)
        buf.push(0xa0);
        // payload: bstr(14)
        buf.push(0x4e);
        buf.extend_from_slice(payload_json);
        // signature: bstr(2)
        buf.push(0x42);
        buf.extend_from_slice(b"xx");

        let extracted = parse_cose_sign1_payload(&buf).unwrap();
        assert_eq!(extracted, payload_json);

        // Also test EndorsementResponse::payload_json()
        let resp = EndorsementResponse {
            mrtd: "TEST".into(),
            data: buf,
            content_type: "application/cose".into(),
        };
        let json = resp.payload_json().unwrap();
        assert_eq!(json["hello"], "ok");
    }

    #[test]
    fn parse_cose_sign1_with_2byte_lengths() {
        // COSE_Sign1 with a protected header whose length needs 2 bytes (> 23)
        let prot = vec![0u8; 100]; // 100-byte protected headers
        let payload = br#"{"x":1}"#;
        let mut buf = vec![
            0xd2, // CBOR tag(18)
            0x84, // array(4)
            0x58, // bstr with 1-byte length prefix (major 2, addl 24)
            100,  // length
        ];
        buf.extend_from_slice(&prot);
        // map(0)
        buf.push(0xa0);
        // payload bstr
        buf.push(0x47); // bstr(7)
        buf.extend_from_slice(payload);
        // signature bstr(0)
        buf.push(0x40);

        let extracted = parse_cose_sign1_payload(&buf).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn parse_cose_sign1_with_map_unprotected() {
        // COSE_Sign1 where unprotected headers is map(1) with tstr key/value
        let payload = br#"{"a":"b"}"#;
        let mut buf = vec![
            0xd2, // CBOR tag(18)
            0x84, // array(4)
            0x40, // protected: bstr(0)
            0xa1, // unprotected: map(1)
            0x63, // tstr(3)
        ];
        buf.extend_from_slice(b"foo");
        buf.push(0x63);
        buf.extend_from_slice(b"bar");
        // payload
        buf.push(0x49); // bstr(9)
        buf.extend_from_slice(payload);
        // signature
        buf.push(0x40);

        let extracted = parse_cose_sign1_payload(&buf).unwrap();
        assert_eq!(extracted, payload);
    }
}
