pub mod consts;
pub mod keygen;
pub mod log;
pub mod patch;
pub mod proxy;
pub mod server;
pub mod version;

use crate::log::file_log;
use std::ffi::c_void;
use std::ptr;

const _: () = {
    assert!(
        !consts::PRIV_KEY.is_empty(),
        "PRIV_KEY in src/consts.rs must not be empty! Generate keys with `cargo run -- -keys`"
    );
    assert!(
        !consts::PUB_KEY.is_empty(),
        "PUB_KEY in src/consts.rs must not be empty! Generate keys with `cargo run -- -keys`"
    );
};

const DLL_PROCESS_ATTACH: u32 = 1;
const DLL_PROCESS_DETACH: u32 = 0;
const ATTACH_PARENT_PROCESS: u32 = 0xFFFFFFFF;
const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn DisableThreadLibraryCalls(hLibModule: *mut c_void) -> i32;
    fn AttachConsole(dwProcessId: u32) -> i32;
    fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
    fn WriteFile(
        hFile: *mut c_void,
        lpBuffer: *const u8,
        nNumberOfBytesToWrite: u32,
        lpNumberOfBytesWritten: *mut u32,
        lpOverlapped: *mut c_void,
    ) -> i32;
    fn ExitProcess(uExitCode: u32) -> !;
}

pub use proxy::{PlaySoundW, timeBeginPeriod, timeEndPeriod, timeGetTime};

#[unsafe(no_mangle)]
pub extern "system" fn StopServer() {
    server::stop_server();
}

#[unsafe(no_mangle)]
pub extern "system" fn GenerateKeys() {
    let (priv_b64, pub_b64) = keygen::generate_keypair();
    let output = keygen::format_keypair_output(&priv_b64, &pub_b64);
    version::show_info_box("Lumabar - Key Generator", &output);
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(hinst: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    match reason {
        DLL_PROCESS_ATTACH => {
            unsafe {
                DisableThreadLibraryCalls(hinst);
            }
            file_log("[lumierre] DLL_PROCESS_ATTACH\n");

            let args: Vec<String> = std::env::args().collect();
            if args
                .iter()
                .any(|arg| arg == "-keys" || arg == "--generate-keys")
            {
                let (priv_b64, pub_b64) = keygen::generate_keypair();
                let output = keygen::format_keypair_output(&priv_b64, &pub_b64);

                let mut attached = false;
                unsafe {
                    if AttachConsole(ATTACH_PARENT_PROCESS) != 0 {
                        attached = true;
                        let h = GetStdHandle(STD_OUTPUT_HANDLE);
                        if !h.is_null() && h != (0xFFFFFFFF as *mut c_void) {
                            let mut written = 0;
                            WriteFile(
                                h,
                                output.as_ptr(),
                                output.len() as u32,
                                &mut written,
                                ptr::null_mut(),
                            );
                        }
                    }
                }

                if !attached {
                    version::show_info_box("Lumabar - Key Generator", &output);
                }

                unsafe {
                    ExitProcess(0);
                }
            }

            match version::detect_version() {
                Ok(profile) => {
                    file_log(&format!(
                        "[lumierre] Detected Lumabar version: {}\n",
                        profile.version
                    ));
                    if patch::apply_patches(profile) {
                        server::start_server();
                    } else {
                        file_log("[lumierre] Memory patching failed! Server not started.\n");
                    }
                }
                Err(err) => {
                    file_log(&format!("[lumierre] Version check failed: {err}\n"));
                }
            }
        }
        DLL_PROCESS_DETACH => {
            file_log("[lumierre] DLL_PROCESS_DETACH\n");
            server::stop_server();
        }
        _ => {}
    }
    1
}
