// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::tpm::types::PcrAlgorithm;
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Deserialize;

#[cfg(target_os = "windows")]
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ,
};

const SYSTEMD_EVENT_TYPE: u32 = 0x8000_00E0;

const MAX_DIGEST_COUNT: u32 = 32;
const MAX_EVENT_DATA_SIZE: usize = 2 * 1024 * 1024; // safety bound (2 MiB)
const SPEC_ID_EVENT_TYPE: u32 = 0x0000_0003;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DigestEncoding {
    Auto,
    WithPrefix,
}

pub const DEFAULT_EVENT_LOG_PATHS: &[&str] = &[
    "/sys/kernel/security/tpm0/binary_bios_measurements",
    "/sys/kernel/security/tpm/binary_bios_measurements",
    "/sys/firmware/acpi/tables/data/TCG0",
    "/run/log/systemd/tpm2-measure.log",
];

#[cfg(target_os = "windows")]
const MEASUREDBOOT_BASE_PATHS: &[&str] = &[
    r"C:\Windows\Logs\MeasuredBoot",
    r"C:\Windows\Logs\MeasuredBoot\Supplemental",
    r"C:\Windows\System32\LogFiles\MeasuredBoot",
];

#[derive(Debug, Clone)]
pub struct EventLog {
    pub events: Vec<Event>,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub pcr_index: u32,
    pub event_type: u32,
    pub digests: Vec<EventDigest>,
    pub event_data: Vec<u8>,
}

impl Event {
    pub fn digest_for_algorithm(&self, alg: PcrAlgorithm) -> Option<&[u8]> {
        let alg_id = alg.to_alg_id();
        self.digests
            .iter()
            .find(|d| d.alg_id == alg_id)
            .map(|d| d.digest.as_slice())
    }
}

#[derive(Debug, Clone)]
pub struct EventDigest {
    pub alg_id: u16,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SpecIdEvent {
    pub signature: String,
    pub platform_class: u32,
    pub spec_version_major: u8,
    pub spec_version_minor: u8,
    pub spec_errata: u8,
    pub uintn_size: u8,
    pub algorithms: Vec<SpecIdAlgorithm>,
    pub vendor_info: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SpecIdAlgorithm {
    pub algorithm_id: u16,
    pub digest_size: u16,
}

pub fn load_event_logs(path: Option<&Path>) -> io::Result<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    match path {
        Some(p) => load_explicit_logs(p),
        None => load_default_logs(),
    }
}

#[cfg(not(target_os = "windows"))]
fn load_default_logs() -> io::Result<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    let mut logs = Vec::new();
    let mut sources = Vec::new();
    let mut last_err: Option<io::Error> = None;
    for candidate in DEFAULT_EVENT_LOG_PATHS {
        let candidate_path = Path::new(candidate);
        match fs::read(candidate_path) {
            Ok(bytes) => {
                logs.push(bytes);
                sources.push(candidate_path.to_path_buf());
            }
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    last_err = Some(io::Error::new(
                        err.kind(),
                        format!("{}: {err}", candidate_path.display()),
                    ));
                }
            }
        }
    }

    if logs.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "TPM event log not found in default locations",
            )
        }));
    }

    Ok((logs, sources))
}

#[cfg(target_os = "windows")]
fn load_default_logs() -> io::Result<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    let mut logs = Vec::new();
    let mut sources = Vec::new();
    let mut last_err: Option<io::Error> = None;

    if let Some((wbcl, source)) = read_windows_wbcl_registry()? {
        if !wbcl.is_empty() {
            logs.push(wbcl);
            sources.push(source);
        }
    }

    if let Some(err) = collect_windows_measured_boot_logs(&mut logs, &mut sources) {
        last_err = Some(err);
    }

    if logs.is_empty() {
        return Err(last_err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "TPM event log not found in Windows registry or measured boot directories",
            )
        }));
    }

    Ok((logs, sources))
}

#[cfg(target_os = "windows")]
fn collect_windows_measured_boot_logs(
    logs: &mut Vec<Vec<u8>>,
    sources: &mut Vec<PathBuf>,
) -> Option<io::Error> {
    let mut last_err: Option<io::Error> = None;

    for base in MEASUREDBOOT_BASE_PATHS {
        let dir = Path::new(base);
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    last_err = Some(io::Error::new(
                        err.kind(),
                        format!("{}: {err}", dir.display()),
                    ));
                }
                continue;
            }
        };

        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => {
                    let file_type = match entry.file_type() {
                        Ok(ft) => ft,
                        Err(err) => {
                            last_err = Some(io::Error::new(
                                err.kind(),
                                format!("{}: {err}", entry.path().display()),
                            ));
                            continue;
                        }
                    };
                    if !file_type.is_file() {
                        continue;
                    }
                    let path = entry.path();
                    let is_bin = path
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .map(|ext| ext.eq_ignore_ascii_case("bin"))
                        .unwrap_or(false);
                    if !is_bin {
                        continue;
                    }
                    paths.push(path);
                }
                Err(err) => {
                    last_err = Some(io::Error::new(
                        err.kind(),
                        format!("{}: {err}", dir.display()),
                    ));
                }
            }
        }

        paths.sort();

        for path in paths {
            match fs::read(&path) {
                Ok(bytes) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    logs.push(bytes);
                    sources.push(path);
                }
                Err(err) => {
                    last_err = Some(io::Error::new(
                        err.kind(),
                        format!("{}: {err}", path.display()),
                    ));
                }
            }
        }
    }

    last_err
}

#[cfg(target_os = "windows")]
fn read_windows_wbcl_registry() -> io::Result<Option<(Vec<u8>, PathBuf)>> {
    const KEY_PATH: &str = r"SYSTEM\CurrentControlSet\Control\IntegrityServices";
    const VALUE_NAME: &str = "WBCL";

    unsafe {
        let mut hkey: isize = 0;
        let key_wide: Vec<u16> = KEY_PATH.encode_utf16().chain([0]).collect();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_wide.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        );
        if status != 0 {
            let err = io::Error::from_raw_os_error(status as i32);
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) {
                return Ok(None);
            }
            return Err(err);
        }

        let value_wide: Vec<u16> = VALUE_NAME.encode_utf16().chain([0]).collect();
        let mut data_len: u32 = 0;
        let status = RegQueryValueExW(
            hkey,
            value_wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut data_len,
        );
        if status != 0 {
            let err = io::Error::from_raw_os_error(status as i32);
            RegCloseKey(hkey);
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) {
                return Ok(None);
            }
            return Err(err);
        }

        if data_len == 0 {
            RegCloseKey(hkey);
            return Ok(None);
        }

        let mut buffer = vec![0u8; data_len as usize];
        let status = RegQueryValueExW(
            hkey,
            value_wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            &mut data_len,
        );
        RegCloseKey(hkey);
        if status != 0 {
            let err = io::Error::from_raw_os_error(status as i32);
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ) {
                return Ok(None);
            }
            return Err(err);
        }

        buffer.truncate(data_len as usize);
        Ok(Some((
            buffer,
            PathBuf::from(r"HKLM\SYSTEM\CurrentControlSet\Control\IntegrityServices\WBCL"),
        )))
    }
}

pub fn load_event_log(path: Option<&Path>) -> io::Result<(Vec<u8>, PathBuf)> {
    let (logs, sources) = load_event_logs(path)?;
    let mut log_iter = logs.into_iter();
    let mut source_iter = sources.into_iter();
    match (log_iter.next(), source_iter.next()) {
        (Some(log), Some(source)) => Ok((log, source)),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "TPM event log not found in provided locations",
        )),
    }
}

pub fn parse_event_log(data: &[u8]) -> io::Result<EventLog> {
    parse_event_log_with_event1_spec(data)
        .or_else(|_| parse_event_log_event2(data))
        .or_else(|_| parse_event_log_event1(data))
        .or_else(|_| parse_json_event_log(data))
}

fn parse_event_log_with_event1_spec(data: &[u8]) -> io::Result<EventLog> {
    let mut cursor = 0usize;
    let mut events = Vec::new();
    let spec_event = parse_event1_entry(data, &mut cursor)?;
    let mut alg_size_overrides: BTreeMap<u16, usize> = BTreeMap::new();
    let mut spec_version_major = 0u8;
    let mut has_multiple_algorithms = false;

    if let Some(spec) = try_parse_spec_id_event(&spec_event.event_data) {
        spec_version_major = spec.spec_version_major;
        for alg in &spec.algorithms {
            if alg.digest_size == 0 {
                continue;
            }
            alg_size_overrides.insert(alg.algorithm_id, alg.digest_size as usize);
        }
        has_multiple_algorithms = spec
            .algorithms
            .iter()
            .any(|alg| alg.algorithm_id != PcrAlgorithm::Sha1.to_alg_id());
    }

    events.push(spec_event);

    if spec_version_major >= 2 || has_multiple_algorithms {
        parse_event2_entries_from(data, &mut cursor, &mut events, &mut alg_size_overrides)?;
    } else {
        parse_event1_entries_from(data, &mut cursor, &mut events)?;
    }

    Ok(EventLog { events })
}

fn parse_event_log_event2(data: &[u8]) -> io::Result<EventLog> {
    let mut cursor = 0usize;
    let mut events = Vec::new();
    let mut alg_size_overrides: BTreeMap<u16, usize> = BTreeMap::new();
    parse_event2_entries_from(data, &mut cursor, &mut events, &mut alg_size_overrides)?;
    Ok(EventLog { events })
}

fn parse_event_log_event1(data: &[u8]) -> io::Result<EventLog> {
    let mut cursor = 0usize;
    let mut events = Vec::new();
    parse_event1_entries_from(data, &mut cursor, &mut events)?;
    Ok(EventLog { events })
}

fn parse_event1_entry(data: &[u8], cursor: &mut usize) -> io::Result<Event> {
    if data.len() - *cursor < 28 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "event log truncated mid-entry",
        ));
    }

    let pcr_index = read_u32_le(data, cursor)?;
    let event_type = read_u32_le(data, cursor)?;
    let digests = parse_event1_digests(data, cursor)?;
    let event_data_size = read_u32_le(data, cursor)? as usize;
    if event_data_size > MAX_EVENT_DATA_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("event data size {event_data_size} exceeds limit"),
        ));
    }
    if *cursor + event_data_size > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "event data exceeds buffer",
        ));
    }
    let event_data = data[*cursor..*cursor + event_data_size].to_vec();
    *cursor += event_data_size;

    Ok(Event {
        pcr_index,
        event_type,
        digests,
        event_data,
    })
}

fn parse_event1_entries_from(
    data: &[u8],
    cursor: &mut usize,
    events: &mut Vec<Event>,
) -> io::Result<()> {
    while *cursor < data.len() {
        let event = parse_event1_entry(data, cursor)?;
        events.push(event);
    }
    Ok(())
}

fn parse_event2_entries_from(
    data: &[u8],
    cursor: &mut usize,
    events: &mut Vec<Event>,
    alg_size_overrides: &mut BTreeMap<u16, usize>,
) -> io::Result<()> {
    while *cursor < data.len() {
        let entry_start = *cursor;
        if data.len() - *cursor < 12 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "event log truncated mid-entry",
            ));
        }

        let pcr_index = read_u32_le(data, cursor)?;
        let event_type = read_u32_le(data, cursor)?;
        let digest_count = read_u32_le(data, cursor)?;
        if digest_count > MAX_DIGEST_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("digest count {digest_count} exceeds safety limit"),
            ));
        }

        let after_header = *cursor;

        let mut digests = parse_event2_digests(
            data,
            cursor,
            event_type,
            digest_count,
            alg_size_overrides,
            DigestEncoding::Auto,
        )?;

        let mut event_data_size = read_u32_le(data, cursor)? as usize;
        if event_data_size > MAX_EVENT_DATA_SIZE || *cursor + event_data_size > data.len() {
            *cursor = after_header;
            digests = parse_event2_digests(
                data,
                cursor,
                event_type,
                digest_count,
                alg_size_overrides,
                DigestEncoding::WithPrefix,
            )?;
            event_data_size = read_u32_le(data, cursor)? as usize;
        }

        if event_data_size > MAX_EVENT_DATA_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("event data size {event_data_size} exceeds limit"),
            ));
        }
        if *cursor + event_data_size > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "event data exceeds buffer",
            ));
        }
        if event_data_size == 0 && event_type == SPEC_ID_EVENT_TYPE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Spec ID event has zero-length payload",
            ));
        }
        let event_data = data[*cursor..*cursor + event_data_size].to_vec();
        *cursor += event_data_size;

        if event_type == SPEC_ID_EVENT_TYPE {
            if let Ok(spec) = parse_spec_id_event(&event_data) {
                for alg in &spec.algorithms {
                    if alg.digest_size == 0 {
                        continue;
                    }
                    alg_size_overrides.insert(alg.algorithm_id, alg.digest_size as usize);
                }
            }
        }

        events.push(Event {
            pcr_index,
            event_type,
            digests,
            event_data,
        });

        if *cursor <= entry_start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "event parser made no progress",
            ));
        }
    }

    Ok(())
}

pub fn replay_pcrs(events: &[Event], alg: PcrAlgorithm) -> BTreeMap<u32, Vec<u8>> {
    let digest_len = alg.digest_len();
    let mut state: BTreeMap<u32, Vec<u8>> = BTreeMap::new();

    for event in events {
        if let Some(measurement) = event.digest_for_algorithm(alg) {
            if measurement.len() != digest_len {
                continue;
            }
            let entry = state
                .entry(event.pcr_index)
                .or_insert_with(|| vec![0u8; digest_len]);
            let new_value = extend_digest(alg, entry, measurement);
            *entry = new_value;
        }
    }

    state
}

pub fn event_type_description(event_type: u32) -> Option<&'static str> {
    match event_type {
        0x00000000 => Some("EV_PREBOOT_CERT"),
        0x00000001 => Some("EV_POST_CODE"),
        0x00000002 => Some("EV_UNUSED"),
        0x00000003 => Some("EV_NO_ACTION"),
        0x00000004 => Some("EV_SEPARATOR"),
        0x00000005 => Some("EV_ACTION"),
        0x00000006 => Some("EV_EVENT_TAG"),
        0x00000007 => Some("EV_S_CRTM_CONTENTS"),
        0x00000008 => Some("EV_S_CRTM_VERSION"),
        0x00000009 => Some("EV_CPU_MICROCODE"),
        0x0000000A => Some("EV_PLATFORM_CONFIG_FLAGS"),
        0x0000000B => Some("EV_TABLE_OF_DEVICES"),
        0x0000000C => Some("EV_COMPACT_HASH"),
        0x0000000D => Some("EV_IPL"),
        0x0000000E => Some("EV_IPL_PARTITION_DATA"),
        0x0000000F => Some("EV_NONHOST_CODE"),
        0x00000010 => Some("EV_NONHOST_CONFIG"),
        0x00000011 => Some("EV_NONHOST_INFO"),
        0x00000012 => Some("EV_OMIT_BOOT_DEVICE_EVENTS"),
        0x80000000 => Some("EV_EFI_EVENT_BASE"),
        0x80000001 => Some("EV_EFI_VARIABLE_DRIVER_CONFIG"),
        0x80000002 => Some("EV_EFI_VARIABLE_BOOT"),
        0x80000003 => Some("EV_EFI_BOOT_SERVICES_APPLICATION"),
        0x80000004 => Some("EV_EFI_BOOT_SERVICES_DRIVER"),
        0x80000005 => Some("EV_EFI_RUNTIME_SERVICES_DRIVER"),
        0x80000006 => Some("EV_EFI_GPT_EVENT"),
        0x80000007 => Some("EV_EFI_ACTION"),
        0x80000008 => Some("EV_EFI_PLATFORM_FIRMWARE_BLOB"),
        0x80000009 => Some("EV_EFI_HANDOFF_TABLES"),
        0x8000000A => Some("EV_EFI_VARIABLE_AUTHORITY"),
        0x800000E0 => Some("EV_SYSTEMD_MEASURE"),
        _ => None,
    }
}

pub fn try_parse_spec_id_event(data: &[u8]) -> Option<SpecIdEvent> {
    parse_spec_id_event(data).ok()
}

pub fn is_mostly_printable(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let printable = data
        .iter()
        .filter(|b| matches!(b, 0x20..=0x7E | b'\n' | b'\r' | b'\t'))
        .count();
    printable * 100 / data.len().max(1) >= 80
}

fn extend_digest(alg: PcrAlgorithm, current: &[u8], measurement: &[u8]) -> Vec<u8> {
    match alg {
        PcrAlgorithm::Sha1 => {
            let mut hasher = Sha1::new();
            hasher.update(current);
            hasher.update(measurement);
            hasher.finalize().to_vec()
        }
        PcrAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(current);
            hasher.update(measurement);
            hasher.finalize().to_vec()
        }
        PcrAlgorithm::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(current);
            hasher.update(measurement);
            hasher.finalize().to_vec()
        }
    }
}

fn parse_spec_id_event(data: &[u8]) -> io::Result<SpecIdEvent> {
    if data.len() < 16 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "spec id event too short",
        ));
    }
    let signature_bytes = &data[..16];
    let signature = String::from_utf8_lossy(signature_bytes)
        .trim_end_matches('\0')
        .to_string();
    if !signature.starts_with("Spec ID Event") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing Spec ID signature",
        ));
    }
    let mut cursor = 16usize;
    let platform_class = read_u32_le(data, &mut cursor)?;
    if cursor + 4 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "spec id version truncated",
        ));
    }
    let spec_version_major = data[cursor];
    let spec_version_minor = data[cursor + 1];
    let spec_errata = data[cursor + 2];
    let uintn_size = data[cursor + 3];
    cursor += 4;

    let algorithm_count = read_u32_le(data, &mut cursor)?;
    if algorithm_count > MAX_DIGEST_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("spec id algorithm count {algorithm_count} exceeds limit"),
        ));
    }
    let mut algorithms = Vec::with_capacity(algorithm_count as usize);
    for _ in 0..algorithm_count {
        let alg_id = read_u16_le(data, &mut cursor)?;
        let digest_size = read_u16_le(data, &mut cursor)?;
        algorithms.push(SpecIdAlgorithm {
            algorithm_id: alg_id,
            digest_size,
        });
    }

    if cursor >= data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "spec id vendor info missing",
        ));
    }
    let vendor_size = data[cursor] as usize;
    cursor += 1;
    if cursor + vendor_size > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "spec id vendor info truncated",
        ));
    }
    let vendor_info = data[cursor..cursor + vendor_size].to_vec();

    Ok(SpecIdEvent {
        signature,
        platform_class,
        spec_version_major,
        spec_version_minor,
        spec_errata,
        uintn_size,
        algorithms,
        vendor_info,
    })
}

fn parse_event1_digests(data: &[u8], cursor: &mut usize) -> io::Result<Vec<EventDigest>> {
    let sha1_len = PcrAlgorithm::Sha1.digest_len();
    let end = (*cursor)
        .checked_add(sha1_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "digest overflow"))?;
    if end > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "digest exceeds buffer",
        ));
    }
    let digest = data[*cursor..end].to_vec();
    *cursor = end;
    Ok(vec![EventDigest {
        alg_id: PcrAlgorithm::Sha1.to_alg_id(),
        digest,
    }])
}

fn parse_event2_digests(
    data: &[u8],
    cursor: &mut usize,
    event_type: u32,
    digest_count: u32,
    alg_size_overrides: &BTreeMap<u16, usize>,
    encoding: DigestEncoding,
) -> io::Result<Vec<EventDigest>> {
    let mut digests = Vec::with_capacity(digest_count as usize);
    for _ in 0..digest_count {
        let alg_id = read_u16_le(data, cursor)?;
        let mut digest_len = digest_len_for_alg(alg_id, alg_size_overrides).unwrap_or(0);
        let remaining = data.len().saturating_sub(*cursor);

        if matches!(encoding, DigestEncoding::WithPrefix) || digest_len == 0 {
            if remaining < 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "digest length prefix truncated",
                ));
            }
            digest_len = read_u16_le(data, cursor)? as usize;
        } else if remaining >= 2 {
            let possible_len = u16::from_le_bytes([data[*cursor], data[*cursor + 1]]) as usize;
            if possible_len == digest_len && remaining >= digest_len + 2 {
                *cursor += 2;
            }
        }

        if digest_len == 0 {
            if event_type == SPEC_ID_EVENT_TYPE {
                digests.push(EventDigest {
                    alg_id,
                    digest: Vec::new(),
                });
                continue;
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown digest length for algorithm 0x{alg_id:04x}"),
            ));
        }

        if digest_len > data.len().saturating_sub(*cursor) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "digest exceeds buffer",
            ));
        }

        let end = (*cursor)
            .checked_add(digest_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "digest overflow"))?;
        let digest = data[*cursor..end].to_vec();
        *cursor = end;
        digests.push(EventDigest { alg_id, digest });
    }
    Ok(digests)
}

fn read_u16_le(data: &[u8], cursor: &mut usize) -> io::Result<u16> {
    if *cursor + 2 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "u16 read past end",
        ));
    }
    let value = u16::from_le_bytes([data[*cursor], data[*cursor + 1]]);
    *cursor += 2;
    Ok(value)
}

fn read_u32_le(data: &[u8], cursor: &mut usize) -> io::Result<u32> {
    if *cursor + 4 > data.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "u32 read past end",
        ));
    }
    let value = u32::from_le_bytes([
        data[*cursor],
        data[*cursor + 1],
        data[*cursor + 2],
        data[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn digest_len_for_alg(alg_id: u16, overrides: &BTreeMap<u16, usize>) -> Option<usize> {
    if let Some(len) = overrides.get(&alg_id) {
        return Some(*len);
    }
    PcrAlgorithm::from_alg_id(alg_id).map(|alg| alg.digest_len())
}

fn load_explicit_logs(path: &Path) -> io::Result<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    let metadata = fs::metadata(path)?;
    if metadata.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)?
            .filter_map(|res| res.ok())
            .filter_map(|entry| match entry.file_type() {
                Ok(ft) if ft.is_file() => Some(entry.path()),
                _ => None,
            })
            .collect();
        entries.sort();
        if entries.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("No files found in {}", path.display()),
            ));
        }
        load_from_paths(entries)
    } else if metadata.is_file() {
        match fs::read(path) {
            Ok(bytes) => Ok((vec![bytes], vec![path.to_path_buf()])),
            Err(err) => Err(io::Error::new(
                err.kind(),
                format!("{}: {err}", path.display()),
            )),
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Unsupported path type: {}", path.display()),
        ))
    }
}

fn load_from_paths(paths: Vec<PathBuf>) -> io::Result<(Vec<Vec<u8>>, Vec<PathBuf>)> {
    let mut logs = Vec::new();
    let mut sources = Vec::new();
    for path in paths {
        match fs::read(&path) {
            Ok(bytes) => {
                logs.push(bytes);
                sources.push(path);
            }
            Err(err) => {
                return Err(io::Error::new(
                    err.kind(),
                    format!("{}: {err}", path.display()),
                ));
            }
        }
    }
    if logs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No event log data located",
        ));
    }
    Ok((logs, sources))
}

fn parse_json_event_log(data: &[u8]) -> io::Result<EventLog> {
    let normalized: Vec<u8> = data
        .iter()
        .map(|b| if *b == 0x1e { b'\n' } else { *b })
        .collect();
    let text = std::str::from_utf8(&normalized).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("text event log is not valid UTF-8: {err}"),
        )
    })?;

    let mut events = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: JsonTextEvent = serde_json::from_str(trimmed).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("json event parse error on line {}: {err}", idx + 1),
            )
        })?;
        let event = convert_json_event(trimmed, parsed)?;
        events.push(event);
    }

    if events.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no JSON events detected",
        ));
    }

    Ok(EventLog { events })
}

fn convert_json_event(raw_line: &str, parsed: JsonTextEvent) -> io::Result<Event> {
    let mut digests = Vec::new();
    for digest in &parsed.digests {
        let alg = match PcrAlgorithm::from_str(&digest.hash_alg) {
            Ok(alg) => alg,
            Err(_) => continue,
        };
        let bytes = hex::decode(&digest.digest).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid hex digest for algorithm {}: {err}",
                    digest.hash_alg
                ),
            )
        })?;
        let expected_len = alg.digest_len();
        if bytes.len() != expected_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "digest length {} for algorithm {} (expected {})",
                    bytes.len(),
                    digest.hash_alg,
                    expected_len
                ),
            ));
        }
        digests.push(EventDigest {
            alg_id: alg.to_alg_id(),
            digest: bytes,
        });
    }

    Ok(Event {
        pcr_index: parsed.pcr,
        event_type: json_event_type(&parsed),
        digests,
        event_data: raw_line.as_bytes().to_vec(),
    })
}

fn json_event_type(event: &JsonTextEvent) -> u32 {
    if let Some(top) = event.event_type.as_deref() {
        if let Some(mapped) = map_json_event_type(top) {
            return mapped;
        }
    }
    if let Some(content) = event.content.as_ref() {
        if let Some(mapped) = extract_event_type_from_content(content) {
            return mapped;
        }
    }
    SYSTEMD_EVENT_TYPE
}

fn extract_event_type_from_content(value: &serde_json::Value) -> Option<u32> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(name)) = map.get("eventType") {
                map_json_event_type(name)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn map_json_event_type(name: &str) -> Option<u32> {
    match name {
        "phase" => Some(0x0000_000D), // Align with EV_IPL for system boot phases
        _ => None,
    }
}

#[derive(Deserialize)]
struct JsonTextEvent {
    pcr: u32,
    #[serde(default)]
    digests: Vec<JsonDigestEntry>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    content: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct JsonDigestEntry {
    #[serde(rename = "hashAlg")]
    hash_alg: String,
    digest: String,
}
