use crate::consts::{PATCH_URL_STR, PUB_KEY_B64};
use crate::log::file_log;
use crate::version::ResolvedVersion;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use std::ffi::c_void;
use std::ptr;

const PAGE_READWRITE: u32 = 0x04;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> *mut c_void;
    fn VirtualProtect(
        lpAddress: *mut c_void,
        dwSize: usize,
        flNewProtect: u32,
        lpflOldProtect: *mut u32,
    ) -> i32;
}

pub unsafe fn patch_rdata(rva: usize, new_bytes: &[u8]) -> bool {
    let base = unsafe { GetModuleHandleW(ptr::null()) } as usize;
    if base == 0 {
        return false;
    }

    let target = (base + rva) as *mut c_void;
    let mut old_protect: u32 = 0;

    let ok = unsafe { VirtualProtect(target, new_bytes.len(), PAGE_READWRITE, &mut old_protect) };
    if ok == 0 {
        return false;
    }

    unsafe {
        ptr::copy_nonoverlapping(new_bytes.as_ptr(), target as *mut u8, new_bytes.len());
        VirtualProtect(target, new_bytes.len(), old_protect, &mut old_protect);
    }

    true
}

pub fn apply_patches(profile: &ResolvedVersion) -> bool {
    file_log(&format!(
        "[lumierre] Applying memory patches for Lumabar {} (URL_RVA: 0x{:X}, PB_RVA: 0x{:X})\n",
        profile.version, profile.url_rva, profile.pb_rva
    ));

    let ok_url = unsafe { patch_rdata(profile.url_rva, PATCH_URL_STR) };
    let ok_pb = unsafe { patch_rdata(profile.pb_rva, PUB_KEY_B64.as_bytes()) };

    if !ok_url || !ok_pb {
        file_log(&format!(
            "[lumierre] Patching failed! (URL: {}, PB: {})\n",
            ok_url, ok_pb
        ));
        return false;
    }

    file_log("[lumierre] Memory patches applied successfully.\n");
    true
}

/// Locates the .rdata section in the main module.
/// Returns (RVA, VirtualSize).
pub unsafe fn get_rdata_section() -> Option<(usize, usize)> {
    unsafe {
        let base = GetModuleHandleW(ptr::null()) as usize;
        if base == 0 {
            return None;
        }

        // Verify DOS signature ("MZ")
        if ptr::read_unaligned(base as *const u16) != 0x5A4D {
            return None;
        }

        let e_lfanew = ptr::read_unaligned((base + 0x3C) as *const i32) as usize;
        let nt_header = base + e_lfanew;

        // Verify NT PE signature ("PE\0\0")
        if ptr::read_unaligned(nt_header as *const u32) != 0x00004550 {
            return None;
        }

        let num_sections = ptr::read_unaligned((nt_header + 6) as *const u16) as usize;
        let opt_hdr_size = ptr::read_unaligned((nt_header + 20) as *const u16) as usize;
        let sec_table = nt_header + 24 + opt_hdr_size;

        for i in 0..num_sections {
            let sec = sec_table + i * 40;
            let sec_name_bytes = std::slice::from_raw_parts(sec as *const u8, 8);
            let sec_name = std::str::from_utf8(sec_name_bytes).unwrap_or("");

            if sec_name.starts_with(".rdata") {
                let virtual_size = ptr::read_unaligned((sec + 8) as *const u32) as usize;
                let virtual_address = ptr::read_unaligned((sec + 12) as *const u32) as usize;
                return Some((virtual_address, virtual_size));
            }
        }

        None
    }
}

/// Searches for a string within the .rdata section of the main module.
/// Returns the RVA (Relative Virtual Address) of the first match if found.
pub unsafe fn find_string(needle: &str) -> Option<usize> {
    unsafe {
        let base = GetModuleHandleW(ptr::null()) as usize;
        if base == 0 || needle.is_empty() {
            return None;
        }

        let (rdata_rva, rdata_size) = get_rdata_section()?;
        let rdata_ptr = (base + rdata_rva) as *const u8;
        let rdata_slice = std::slice::from_raw_parts(rdata_ptr, rdata_size);

        let needle_bytes = needle.as_bytes();
        rdata_slice
            .windows(needle_bytes.len())
            .position(|window| window == needle_bytes)
            .map(|offset| rdata_rva + offset)
    }
}

/// Searches for all occurrences of a string within the .rdata section of the main module.
/// Returns a list of RVAs.
pub unsafe fn find_all_strings(needle: &str) -> Vec<usize> {
    unsafe {
        let base = GetModuleHandleW(ptr::null()) as usize;
        if base == 0 || needle.is_empty() {
            return Vec::new();
        }

        let Some((rdata_rva, rdata_size)) = get_rdata_section() else {
            return Vec::new();
        };

        let rdata_ptr = (base + rdata_rva) as *const u8;
        let rdata_slice = std::slice::from_raw_parts(rdata_ptr, rdata_size);
        let needle_bytes = needle.as_bytes();

        rdata_slice
            .windows(needle_bytes.len())
            .enumerate()
            .filter_map(|(offset, window)| {
                if window == needle_bytes {
                    Some(rdata_rva + offset)
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Reads a string from the given RVA in the main module up to `max_len` bytes.
/// Trims at the first null terminator (`\0`), returning a UTF-8 String.
pub unsafe fn read_string(rva: usize, max_len: usize) -> Option<String> {
    unsafe {
        let base = GetModuleHandleW(ptr::null()) as usize;
        if base == 0 || max_len == 0 {
            return None;
        }

        let ptr = (base + rva) as *const u8;
        let slice = std::slice::from_raw_parts(ptr, max_len);
        let len = slice.iter().position(|&b| b == 0).unwrap_or(max_len);

        Some(String::from_utf8_lossy(&slice[..len]).to_string())
    }
}

fn is_b64_data_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
}

/// Attempts to locate the license server URL RVA (`licserv`) in `.rdata`.
pub unsafe fn autoscan_licserv() -> Option<usize> {
    unsafe {
        let exact = find_all_strings("https://license.lumabar.xyz");
        if exact.len() == 1 {
            return Some(exact[0]);
        }

        let prefix = find_all_strings("https://license.lumabar.");
        if prefix.len() == 1 {
            return Some(prefix[0]);
        }

        let base = GetModuleHandleW(ptr::null()) as usize;
        let (rdata_rva, rdata_size) = get_rdata_section()?;
        let anchors = find_all_strings("Polar not reached");
        if base != 0 && anchors.len() == 1 {
            let start_off = (anchors[0] - rdata_rva).min(rdata_size);
            let end_off = (start_off + 128).min(rdata_size);
            let rdata_slice = std::slice::from_raw_parts((base + rdata_rva) as *const u8, rdata_size);
            let window = &rdata_slice[start_off..end_off];
            if let Some(rel) = window.windows(8).position(|w| w == b"https://") {
                let tail = &window[rel..window.len().min(rel + 48)];
                if tail.windows(7).any(|w| w == b"lumabar") {
                    return Some(rdata_rva + start_off + rel);
                }
            }
        }

        None
    }
}

/// Attempts to locate the embedded Ed25519 verifying key RVA (`pb`) in `.rdata`.
pub unsafe fn autoscan_pb() -> Option<usize> {
    unsafe {
        const KNOWN_PB: &str = "qa3dukOqnwUxD6L7+WM4KcnCUOGRecdIc8cAeyuC48A=";
        let exact = find_all_strings(KNOWN_PB);
        if exact.len() == 1 {
            return Some(exact[0]);
        }

        // Fallback if the official public key rotated: find the 44-byte base64 key
        // sitting immediately before "[license] ... an answer the license server did not sign".
        let base = GetModuleHandleW(ptr::null()) as usize;
        let (rdata_rva, rdata_size) = get_rdata_section()?;
        let anchors = find_all_strings("an answer the license server did not sign");
        if base == 0 || anchors.len() != 1 {
            return None;
        }

        let anchor_off = anchors[0].checked_sub(rdata_rva)?;
        let win_start = anchor_off.saturating_sub(128);
        let rdata_slice = std::slice::from_raw_parts((base + rdata_rva) as *const u8, rdata_size);
        let window = &rdata_slice[win_start..anchor_off];

        if window.len() < 44 {
            return None;
        }

        for pos in (0..=window.len() - 44).rev() {
            let cand = &window[pos..pos + 44];
            if cand[43] != b'=' || !cand[..43].iter().all(|&b| is_b64_data_char(b)) {
                continue;
            }
            if pos > 0 && (is_b64_data_char(window[pos - 1]) || window[pos - 1] == b'=') {
                continue;
            }
            if pos + 44 < window.len() && is_b64_data_char(window[pos + 44]) {
                continue;
            }
            if B64.decode(cand).map(|d| d.len() == 32).unwrap_or(false) {
                return Some(rdata_rva + win_start + pos);
            }
        }

        None
    }
}

/// Autoscans `.rdata` for both `licserv` (URL RVA) and `pb` (Public Key RVA).
/// Returns `Some((url_rva, pb_rva))` only when both targets are resolved.
pub unsafe fn autoscan_offsets() -> Option<(usize, usize)> {
    unsafe {
        let url_rva = autoscan_licserv();
        let pb_rva = autoscan_pb();

        file_log(&format!(
            "[lumierre] Autoscan results: url_rva={:?}, pb_rva={:?}\n",
            url_rva.map(|v| format!("0x{v:X}")),
            pb_rva.map(|v| format!("0x{v:X}"))
        ));

        match (url_rva, pb_rva) {
            (Some(u), Some(p)) => Some((u, p)),
            _ => None,
        }
    }
}
