use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::ptr;

#[link(name = "user32")]
unsafe extern "system" {
    fn MessageBoxW(hWnd: *mut c_void, lpText: *const u16, lpCaption: *const u16, uType: u32)
    -> i32;
}

#[derive(Debug, Clone, Copy)]
pub struct VersionProfile {
    pub version: &'static str,
    pub sha256: &'static str,
    pub url_rva: usize,
    pub pb_rva: usize,
}

pub const SUPPORTED_VERSIONS: &[VersionProfile] = &[
    VersionProfile {
        version: "1.2.28",
        sha256: "484ce4e160a42a5883cee2c8f51d384a5922595846178fb2429455b689bc250f",
        url_rva: 0x135a47e,
        pb_rva: 0x135a093,
    },
    VersionProfile {
        version: "1.2.27",
        sha256: "ef04fee14877329f8c1f351c8dea8de2ae50656e0915f5c4cc5560b21c5eeaab",
        url_rva: 0x13565BE,
        pb_rva: 0x13561D3,
    },
];

pub fn show_error_box(title: &str, message: &str) {
    let wtitle: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let wmsg: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    const MB_OK: u32 = 0x00000000;
    const MB_ICONERROR: u32 = 0x00000010;
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            wmsg.as_ptr(),
            wtitle.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub fn show_info_box(title: &str, message: &str) {
    let wtitle: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let wmsg: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    const MB_OK: u32 = 0x00000000;
    const MB_ICONINFORMATION: u32 = 0x00000040;
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            wmsg.as_ptr(),
            wtitle.as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

pub fn compute_current_exe_sha256() -> Result<(String, String), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get current executable path: {e}"))?;
    let exe_name = exe_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut file = File::open(&exe_path)
        .map_err(|e| format!("Failed to open executable {}: {e}", exe_path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed reading executable: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let hash_hex = format!("{:x}", hasher.finalize());
    Ok((exe_name, hash_hex))
}

pub fn detect_version() -> Result<&'static VersionProfile, String> {
    let (exe_name, current_hash) = compute_current_exe_sha256()?;

    if !exe_name.eq_ignore_ascii_case("lumabar.exe") {
        return Err(format!(
            "Loaded into non-target executable: {exe_name}. Skipping patches."
        ));
    }

    for profile in SUPPORTED_VERSIONS {
        if current_hash.eq_ignore_ascii_case(profile.sha256) {
            return Ok(profile);
        }
    }

    let supported_info = SUPPORTED_VERSIONS
        .iter()
        .map(|v| format!("  - v{} (SHA256: {})", v.version, v.sha256))
        .collect::<Vec<_>>()
        .join("\n");

    let error_msg = format!(
        "Unsupported Lumabar version detected!\n\n\
         Executable:\n  {}\n\n\
         Current SHA256:\n  {}\n\n\
         Supported versions:\n{}\n\n\
         Proxy initialization has been aborted to prevent crashes.",
        exe_name, current_hash, supported_info
    );

    show_error_box("Lumabar Proxy - Unsupported Version", &error_msg);
    Err(error_msg)
}
