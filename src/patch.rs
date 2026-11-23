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
