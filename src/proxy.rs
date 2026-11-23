use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(lpLibFileName: *const u16) -> *mut c_void;
    fn GetProcAddress(hModule: *mut c_void, lpProcName: *const u8) -> *mut c_void;
}

static REAL_WINMM: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

pub unsafe fn get_real_winmm_proc(name: &[u8]) -> *mut c_void {
    let mut mod_handle = REAL_WINMM.load(Ordering::Acquire);
    if mod_handle.is_null() {
        let path: Vec<u16> = "C:\\Windows\\System32\\winmm.dll\0"
            .encode_utf16()
            .collect();
        mod_handle = unsafe { LoadLibraryW(path.as_ptr()) };
        if !mod_handle.is_null() {
            REAL_WINMM.store(mod_handle, Ordering::Release);
        }
    }

    if !mod_handle.is_null() {
        unsafe { GetProcAddress(mod_handle, name.as_ptr()) }
    } else {
        ptr::null_mut()
    }
}

static REAL_PLAY_SOUND: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn PlaySoundW(
    psz_sound: *const u16,
    hmod: *mut c_void,
    fdw_sound: u32,
) -> i32 {
    let mut ptr = REAL_PLAY_SOUND.load(Ordering::Relaxed);
    if ptr.is_null() {
        ptr = unsafe { get_real_winmm_proc(b"PlaySoundW\0") };
        REAL_PLAY_SOUND.store(ptr, Ordering::Relaxed);
    }
    if !ptr.is_null() {
        let f: unsafe extern "system" fn(*const u16, *mut c_void, u32) -> i32 =
            unsafe { std::mem::transmute(ptr) };
        unsafe { f(psz_sound, hmod, fdw_sound) }
    } else {
        0
    }
}

static REAL_TIME_GET_TIME: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn timeGetTime() -> u32 {
    let mut ptr = REAL_TIME_GET_TIME.load(Ordering::Relaxed);
    if ptr.is_null() {
        ptr = unsafe { get_real_winmm_proc(b"timeGetTime\0") };
        REAL_TIME_GET_TIME.store(ptr, Ordering::Relaxed);
    }
    if !ptr.is_null() {
        let f: unsafe extern "system" fn() -> u32 = unsafe { std::mem::transmute(ptr) };
        unsafe { f() }
    } else {
        0
    }
}

static REAL_TIME_BEGIN_PERIOD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn timeBeginPeriod(period: u32) -> u32 {
    let mut ptr = REAL_TIME_BEGIN_PERIOD.load(Ordering::Relaxed);
    if ptr.is_null() {
        ptr = unsafe { get_real_winmm_proc(b"timeBeginPeriod\0") };
        REAL_TIME_BEGIN_PERIOD.store(ptr, Ordering::Relaxed);
    }
    if !ptr.is_null() {
        let f: unsafe extern "system" fn(u32) -> u32 = unsafe { std::mem::transmute(ptr) };
        unsafe { f(period) }
    } else {
        0
    }
}

static REAL_TIME_END_PERIOD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn timeEndPeriod(period: u32) -> u32 {
    let mut ptr = REAL_TIME_END_PERIOD.load(Ordering::Relaxed);
    if ptr.is_null() {
        ptr = unsafe { get_real_winmm_proc(b"timeEndPeriod\0") };
        REAL_TIME_END_PERIOD.store(ptr, Ordering::Relaxed);
    }
    if !ptr.is_null() {
        let f: unsafe extern "system" fn(u32) -> u32 = unsafe { std::mem::transmute(ptr) };
        unsafe { f(period) }
    } else {
        0
    }
}
