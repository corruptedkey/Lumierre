use crate::consts::{PATCH_URL_STR, PUB_KEY_B64};
use crate::log::file_log;
use crate::version::VersionProfile;
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

pub fn apply_patches(profile: &VersionProfile) -> bool {
    file_log(&format!(
        "[lumierre] Applying memory patches for Lumabar v{} (URL_RVA: 0x{:X}, PB_RVA: 0x{:X})\n",
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
