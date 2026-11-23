#[cfg(debug_assertions)]
use std::ffi::CString;
#[cfg(debug_assertions)]
use std::io::Write;

#[cfg(debug_assertions)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn OutputDebugStringA(lpOutputString: *const u8);
}

#[cfg(debug_assertions)]
pub fn debug_log(msg: &str) {
    if let Ok(cstr) = CString::new(msg) {
        unsafe { OutputDebugStringA(cstr.as_ptr() as *const u8) };
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn debug_log(_msg: &str) {}

#[cfg(debug_assertions)]
pub fn file_log(msg: &str) {
    debug_log(msg);
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let path = format!("{}\\com.lumabar.dock\\logs\\proxy.log", local_app_data);
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = f.write_all(msg.as_bytes());
        }
    }
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn file_log(_msg: &str) {}
