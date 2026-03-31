// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal COSE_Sign1 (RFC 9052 §4.2) parser.
//!
//! This module extracts the payload from a COSE_Sign1 envelope without
//! pulling in a full CBOR crate.  Only the subset of CBOR needed to
//! navigate the four-element `COSE_Sign1` array is implemented.
//!
//! ```text
//! COSE_Sign1 = #6.18([       ; CBOR tag 18
//!     protected   : bstr,    ; serialised Headers
//!     unprotected : map,     ; Headers
//!     payload     : bstr,    ; content
//!     signature   : bstr,    ; signature
//! ])
//! ```
//!
//! No signature verification is performed.

use std::io;

// ---- CBOR constants --------------------------------------------------------

/// CBOR major type 0 — unsigned integer.
const CBOR_MAJOR_UINT: u8 = 0;
/// CBOR major type 1 — negative integer.
const CBOR_MAJOR_NINT: u8 = 1;
/// CBOR major type 2 — byte string.
const CBOR_MAJOR_BSTR: u8 = 2;
/// CBOR major type 3 — text string.
const CBOR_MAJOR_TSTR: u8 = 3;
/// CBOR major type 4 — array.
const CBOR_MAJOR_ARRAY: u8 = 4;
/// CBOR major type 5 — map.
const CBOR_MAJOR_MAP: u8 = 5;
/// CBOR major type 6 — tag.
const CBOR_MAJOR_TAG: u8 = 6;
/// CBOR major type 7 — simple values / floats.
const CBOR_MAJOR_SIMPLE: u8 = 7;

/// CBOR additional-info value meaning "1-byte length follows".
const CBOR_ADDL_1BYTE: u8 = 24;
/// CBOR additional-info value meaning "2-byte length follows".
const CBOR_ADDL_2BYTE: u8 = 25;
/// CBOR additional-info value meaning "4-byte length follows".
const CBOR_ADDL_4BYTE: u8 = 26;
/// CBOR additional-info value meaning "8-byte length follows".
const CBOR_ADDL_8BYTE: u8 = 27;

// ---- COSE_Sign1 constants --------------------------------------------------

/// CBOR tag for COSE_Sign1 (RFC 9052 §4.2).
const COSE_SIGN1_TAG: u64 = 18;
/// Expected number of elements in the COSE_Sign1 array.
const COSE_SIGN1_ARRAY_LEN: u64 = 4;

/// Encoded first byte: CBOR tag(18) in one-byte form (`0xc0 | 18 = 0xd2`).
pub const COSE_SIGN1_TAG_BYTE: u8 = 0xd2;
/// Encoded second byte: CBOR array(4) (`0x80 | 4 = 0x84`).
pub const COSE_SIGN1_ARRAY_BYTE: u8 = 0x84;

/// Minimum size of a COSE_Sign1 envelope (tag + array head + 4 empty items).
const COSE_SIGN1_MIN_SIZE: usize = 4;

// ---- Public API ------------------------------------------------------------

/// Extract the payload bytes from a COSE_Sign1 binary.
///
/// Returns the raw payload byte string (element index 2 of the array).
/// The caller decides how to interpret these bytes (e.g. parse as JSON).
pub fn parse_cose_sign1_payload(data: &[u8]) -> io::Result<Vec<u8>> {
    let err = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, msg.to_string());

    if data.len() < COSE_SIGN1_MIN_SIZE {
        return Err(err("data too short for COSE_Sign1"));
    }

    // Expect CBOR tag 18 followed by array(4).
    if data[0] != COSE_SIGN1_TAG_BYTE {
        return Err(err(&format!(
            "expected CBOR tag {COSE_SIGN1_TAG} (0x{COSE_SIGN1_TAG_BYTE:02x}), got 0x{:02x}",
            data[0]
        )));
    }
    if data[1] != COSE_SIGN1_ARRAY_BYTE {
        return Err(err(&format!(
            "expected CBOR array({COSE_SIGN1_ARRAY_LEN}) (0x{COSE_SIGN1_ARRAY_BYTE:02x}), got 0x{:02x}",
            data[1]
        )));
    }

    let mut pos: usize = 2;

    // Skip element 0: protected headers (bstr).
    pos = skip_cbor_item(data, pos).map_err(|e| err(&e))?;

    // Skip element 1: unprotected headers (map).
    pos = skip_cbor_item(data, pos).map_err(|e| err(&e))?;

    // Element 2: payload (bstr) — this is what we want.
    let (payload, _) = read_cbor_bstr(data, pos).map_err(|e| err(&e))?;

    Ok(payload.to_vec())
}

// ---- Minimal CBOR helpers --------------------------------------------------

/// Read the CBOR "head" (major type + argument) at `pos`.
///
/// Returns `(major_type, argument_value, new_pos)`.
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
        CBOR_ADDL_1BYTE => {
            if p >= data.len() {
                return Err("truncated CBOR 1-byte length".into());
            }
            let v = u64::from(data[p]);
            p += 1;
            v
        }
        CBOR_ADDL_2BYTE => {
            if p + 2 > data.len() {
                return Err("truncated CBOR 2-byte length".into());
            }
            let v = u64::from(u16::from_be_bytes([data[p], data[p + 1]]));
            p += 2;
            v
        }
        CBOR_ADDL_4BYTE => {
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
        CBOR_ADDL_8BYTE => {
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
    if major != CBOR_MAJOR_BSTR && major != CBOR_MAJOR_TSTR {
        return Err(format!(
            "expected bstr/tstr (major {CBOR_MAJOR_BSTR}/{CBOR_MAJOR_TSTR}) at offset {pos}, got major {major}"
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
        CBOR_MAJOR_UINT | CBOR_MAJOR_NINT => Ok(p),
        CBOR_MAJOR_BSTR | CBOR_MAJOR_TSTR => {
            let len = value as usize;
            let end = p.checked_add(len).ok_or("CBOR length overflow")?;
            if end > data.len() {
                return Err(format!("truncated CBOR bstr/tstr at offset {pos}"));
            }
            Ok(end)
        }
        CBOR_MAJOR_ARRAY => {
            let count = value as usize;
            let mut cur = p;
            for _ in 0..count {
                cur = skip_cbor_item(data, cur)?;
            }
            Ok(cur)
        }
        CBOR_MAJOR_MAP => {
            let count = value as usize;
            let mut cur = p;
            for _ in 0..count {
                cur = skip_cbor_item(data, cur)?; // key
                cur = skip_cbor_item(data, cur)?; // value
            }
            Ok(cur)
        }
        CBOR_MAJOR_TAG => skip_cbor_item(data, p), // skip the wrapped item
        CBOR_MAJOR_SIMPLE => Ok(p),                // simple values / float
        _ => Err(format!("unknown CBOR major type {major}")),
    }
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a CBOR tag(18) + array(4) header.
    fn cose_sign1_header() -> Vec<u8> {
        vec![COSE_SIGN1_TAG_BYTE, COSE_SIGN1_ARRAY_BYTE]
    }

    /// Helper: encode a CBOR bstr with the given content.
    fn cbor_bstr(content: &[u8]) -> Vec<u8> {
        let len = content.len();
        let mut buf = Vec::new();
        if len <= 23 {
            buf.push((CBOR_MAJOR_BSTR << 5) | len as u8);
        } else if len <= 0xff {
            buf.push((CBOR_MAJOR_BSTR << 5) | CBOR_ADDL_1BYTE);
            buf.push(len as u8);
        } else {
            buf.push((CBOR_MAJOR_BSTR << 5) | CBOR_ADDL_2BYTE);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        buf.extend_from_slice(content);
        buf
    }

    /// Helper: CBOR map(0).
    fn cbor_empty_map() -> Vec<u8> {
        vec![(CBOR_MAJOR_MAP << 5)]
    }

    /// Helper: CBOR tstr with the given text.
    fn cbor_tstr(text: &str) -> Vec<u8> {
        let len = text.len();
        let mut buf = Vec::new();
        if len <= 23 {
            buf.push((CBOR_MAJOR_TSTR << 5) | len as u8);
        } else {
            buf.push((CBOR_MAJOR_TSTR << 5) | CBOR_ADDL_1BYTE);
            buf.push(len as u8);
        }
        buf.extend_from_slice(text.as_bytes());
        buf
    }

    #[test]
    fn parse_cose_sign1_too_short() {
        assert!(parse_cose_sign1_payload(&[]).is_err());
        assert!(parse_cose_sign1_payload(&[COSE_SIGN1_TAG_BYTE]).is_err());
        assert!(parse_cose_sign1_payload(&[COSE_SIGN1_TAG_BYTE, COSE_SIGN1_ARRAY_BYTE]).is_err());
    }

    #[test]
    fn parse_cose_sign1_wrong_tag() {
        let wrong_tag = 0xd3; // tag(19) instead of tag(18)
        let mut buf = vec![wrong_tag, COSE_SIGN1_ARRAY_BYTE];
        buf.extend_from_slice(&cbor_bstr(b""));
        buf.extend_from_slice(&cbor_empty_map());
        buf.extend_from_slice(&cbor_bstr(b""));
        buf.extend_from_slice(&cbor_bstr(b""));

        let err = parse_cose_sign1_payload(&buf).unwrap_err();
        assert!(
            err.to_string().contains(&format!("0x{wrong_tag:02x}")),
            "{err}"
        );
    }

    #[test]
    fn parse_cose_sign1_wrong_array_len() {
        let array3 = (CBOR_MAJOR_ARRAY << 5) | 3; // array(3) instead of array(4)
        let mut buf = vec![COSE_SIGN1_TAG_BYTE, array3];
        buf.extend_from_slice(&cbor_bstr(b""));
        buf.extend_from_slice(&cbor_empty_map());
        buf.extend_from_slice(&cbor_bstr(b""));

        let err = parse_cose_sign1_payload(&buf).unwrap_err();
        assert!(
            err.to_string().contains(&format!("0x{array3:02x}")),
            "{err}"
        );
    }

    #[test]
    fn parse_cose_sign1_valid() {
        let payload_json = br#"{"hello":"ok"}"#;

        let mut buf = cose_sign1_header();
        buf.extend_from_slice(&cbor_bstr(b"abc")); // protected headers
        buf.extend_from_slice(&cbor_empty_map()); // unprotected headers
        buf.extend_from_slice(&cbor_bstr(payload_json)); // payload
        buf.extend_from_slice(&cbor_bstr(b"xx")); // signature

        let extracted = parse_cose_sign1_payload(&buf).unwrap();
        assert_eq!(extracted, payload_json);
    }

    #[test]
    fn parse_cose_sign1_with_2byte_lengths() {
        // Protected header with length > 23 to exercise the 1-byte length path.
        let prot = vec![0u8; 100];
        let payload = br#"{"x":1}"#;

        let mut buf = cose_sign1_header();
        buf.extend_from_slice(&cbor_bstr(&prot));
        buf.extend_from_slice(&cbor_empty_map());
        buf.extend_from_slice(&cbor_bstr(payload));
        buf.extend_from_slice(&cbor_bstr(b""));

        let extracted = parse_cose_sign1_payload(&buf).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn parse_cose_sign1_with_map_unprotected() {
        // Unprotected headers = map(1) { "foo" : "bar" }
        let payload = br#"{"a":"b"}"#;

        let mut buf = cose_sign1_header();
        buf.extend_from_slice(&cbor_bstr(b"")); // protected
                                                // unprotected: map(1) { tstr "foo" : tstr "bar" }
        buf.push((CBOR_MAJOR_MAP << 5) | 1);
        buf.extend_from_slice(&cbor_tstr("foo"));
        buf.extend_from_slice(&cbor_tstr("bar"));
        // payload
        buf.extend_from_slice(&cbor_bstr(payload));
        // signature
        buf.extend_from_slice(&cbor_bstr(b""));

        let extracted = parse_cose_sign1_payload(&buf).unwrap();
        assert_eq!(extracted, payload);
    }
}
