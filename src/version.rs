use sha2::{Digest, Sha256};
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::ptr;

use crate::patch::{find_all_strings, read_string};

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

#[derive(Debug, Clone)]
pub struct ResolvedVersion {
    pub version: String,
    pub url_rva: usize,
    pub pb_rva: usize,
    pub autoscanned: bool,
}

pub const SUPPORTED_VERSIONS: &[VersionProfile] = &[
    VersionProfile {
        version: "1.2.30",
        sha256: "0e79109155125a8640d7dcdb48bd619f7d43a26142c465e31bdd02ae8906eb02",
        url_rva: 0x13a3a3e,
        pb_rva: 0x13a364e,
    },
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

fn detect_build_version() -> String {
    for rva in unsafe { find_all_strings("build ") } {
        if let Some(text) = unsafe { read_string(rva, 64) } {
            if let Some(rest) = text.strip_prefix("build ") {
                let raw: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                let candidate = raw.trim_end_matches('.');

                let is_version =
                    candidate.contains('.') && candidate.split('.').all(|part| !part.is_empty());

                if is_version {
                    return format!("v{}", candidate);
                }
            }
        }
    }
    "unknown".to_string()
}

pub fn detect_version(show_dialog: bool) -> Result<ResolvedVersion, String> {
    let (exe_name, current_hash) = compute_current_exe_sha256()?;

    if !exe_name.eq_ignore_ascii_case("lumabar.exe") {
        return Err(format!(
            "Loaded into non-target executable: {exe_name}. Skipping patches."
        ));
    }

    for profile in SUPPORTED_VERSIONS {
        if current_hash.eq_ignore_ascii_case(profile.sha256) {
            return Ok(ResolvedVersion {
                version: format!("v{}", profile.version),
                url_rva: profile.url_rva,
                pb_rva: profile.pb_rva,
                autoscanned: false,
            });
        }
    }

    let version = detect_build_version();
    if let Some((url_rva, pb_rva)) = unsafe { crate::patch::autoscan_offsets() } {
        return Ok(ResolvedVersion {
            version,
            url_rva,
            pb_rva,
            autoscanned: true,
        });
    }

    let supported_info = SUPPORTED_VERSIONS
        .iter()
        .map(|v| format!("  - v{}", v.version))
        .collect::<Vec<_>>()
        .join("\n");

    let error_msg = format!(
        "Unsupported Lumabar version detected!\n\n\
         Executable: {}\n\n\
         Current version: {}\n\n\
         Supported versions:\n{}\n\n\
         Autoscan failed and Lumierre initialization has been aborted.",
        exe_name, version, supported_info
    );

    if show_dialog {
        show_error_box("Lumabar", &error_msg);
    }
    Err(error_msg)
}
