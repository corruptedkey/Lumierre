use std::ffi::c_void;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

use crate::consts::{ADDR, CUSTOMER_EMAIL, CUSTOMER_NAME, DEFAULT_ACTIVATION_ID, PRIV_KEY_B64};
use crate::log::file_log;

const INFINITE: u32 = 0xFFFFFFFF;

static RUNNING: AtomicBool = AtomicBool::new(false);
static THREAD_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateThread(
        lpThreadAttributes: *mut c_void,
        dwStackSize: usize,
        lpStartAddress: unsafe extern "system" fn(*mut c_void) -> u32,
        lpParameter: *mut c_void,
        dwCreationFlags: u32,
        lpThreadId: *mut u32,
    ) -> *mut c_void;
    fn WaitForSingleObject(hHandle: *mut c_void, dwMilliseconds: u32) -> u32;
    fn CloseHandle(hObject: *mut c_void) -> i32;
}

pub fn router(path: &str) -> Option<&'static str> {
    let clean = path.split('?').next().unwrap_or("").trim_end_matches('/');
    if clean.ends_with("/validate") {
        Some("validate")
    } else if clean.ends_with("/activate") {
        Some("activate")
    } else if clean.ends_with("/deactivate") {
        Some("deactivate")
    } else {
        None
    }
}

pub fn build_payload(req_map: &serde_json::Map<String, Value>, action: &str) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("v".to_string(), json!(1));
    payload.insert("action".to_string(), json!(action));
    payload.insert("status".to_string(), json!(200));

    // lumabar.exe strictly checks these 4 fields at 0x540520:
    // If a field is in request, it MUST be in response payload with identical value.
    // If a field is NOT in request, it MUST NOT be in response payload!
    for field in &["nonce", "key", "activation_id", "label"] {
        if let Some(val) = req_map.get(*field) {
            payload.insert(field.to_string(), val.clone());
        }
    }

    let req_act_id = req_map
        .get("activation_id")
        .and_then(|v| v.as_str())
        .unwrap_or(DEFAULT_ACTIVATION_ID);

    let inner: Value = match action {
        "validate" => json!({
            "status": "granted",
            "activation": {
                "id": req_act_id,
            },
            "activation_id": req_act_id,
            "customer": {
                "name": CUSTOMER_NAME,
                "email": CUSTOMER_EMAIL,
            },
            "customer_name": CUSTOMER_NAME,
            "customer_email": CUSTOMER_EMAIL,
        }),
        "activate" => json!({
            "id": DEFAULT_ACTIVATION_ID,
            "license_key": {
                "customer": {
                    "name": CUSTOMER_NAME,
                    "email": CUSTOMER_EMAIL,
                }
            }
        }),
        "deactivate" => json!({
            "status": "ok"
        }),
        _ => json!({}),
    };

    payload.insert(
        "body".to_string(),
        json!(serde_json::to_string(&inner).unwrap()),
    );

    Value::Object(payload)
}

pub fn sign_response(sk: &SigningKey, payload_obj: Value) -> Vec<u8> {
    let payload_str = serde_json::to_string(&payload_obj).unwrap();
    let sig = sk.sign(payload_str.as_bytes());
    let wrapper = json!({
        "payload": payload_str,
        "sig":     B64.encode(sig.to_bytes()),
    });
    serde_json::to_vec(&wrapper).unwrap()
}

pub fn handle_client(mut stream: TcpStream, sk: SigningKey) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".into());

    let mut buf = vec![0u8; 65536];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    buf.truncate(n);

    let raw = String::from_utf8_lossy(&buf);
    let (headers, body) = match raw.split_once("\r\n\r\n") {
        Some(p) => p,
        None => return,
    };

    let request_line = headers.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("-");
    let path = parts.next().unwrap_or("-");

    let action = match router(path) {
        Some(a) => a,
        None => {
            let _ = stream.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return;
        }
    };

    let req_val: Value =
        serde_json::from_str(body).unwrap_or(Value::Object(serde_json::Map::new()));
    let req_map = req_val.as_object().cloned().unwrap_or_default();

    file_log(&format!(
        "[{peer}] {method} {path} action={action} req={body}\n"
    ));

    let payload_obj = build_payload(&req_map, action);
    let resp_json = sign_response(&sk, payload_obj);

    file_log(&format!(
        "[{peer}] resp={}\n",
        String::from_utf8_lossy(&resp_json)
    ));

    let accept_gzip = headers
        .to_lowercase()
        .lines()
        .any(|l| l.starts_with("accept-encoding:") && l.contains("gzip"));

    let (body_bytes, enc_hdr) = if accept_gzip {
        use flate2::{Compression, write::GzEncoder};
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&resp_json).ok();
        (
            enc.finish().unwrap_or_default(),
            "Content-Encoding: gzip\r\n",
        )
    } else {
        (resp_json, "")
    };

    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         {enc_hdr}\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body_bytes.len()
    );

    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(&body_bytes);
    let _ = stream.flush();
}

unsafe extern "system" fn server_thread(_param: *mut c_void) -> u32 {
    let priv_bytes: [u8; 32] = B64
        .decode(PRIV_KEY_B64)
        .expect("invalid base64")
        .try_into()
        .expect("must be 32 bytes");
    let sk = &SigningKey::from_bytes(&priv_bytes);
    let pub_b64 = B64.encode(sk.verifying_key().to_bytes());

    file_log("[lumierre] server_thread started\n");
    file_log(&format!("[lumierre] pubkey: {pub_b64}\n"));

    let listener = match TcpListener::bind(ADDR) {
        Ok(l) => {
            file_log(&format!("[lumierre] bound to {ADDR}\n"));
            l
        }
        Err(e) => {
            file_log(&format!("[lumierre] bind failed: {e}\n"));
            RUNNING.store(false, Ordering::SeqCst);
            return 1;
        }
    };

    if let Err(e) = listener.set_nonblocking(true) {
        file_log(&format!("[lumierre] set_nonblocking failed: {e}\n"));
        RUNNING.store(false, Ordering::SeqCst);
        return 1;
    }
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();

    while RUNNING.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let sk = sk.clone();
                workers.push(std::thread::spawn(move || handle_client(stream, sk)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                file_log(&format!("[lumierre] accept error: {e}\n"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        workers.retain(|h| !h.is_finished());
    }

    file_log("[lumierre] shutting down, joining workers...\n");
    for h in workers {
        let _ = h.join();
    }
    file_log("[winmm-proxy] server_thread exited\n");
    0
}

pub fn start_server() -> bool {
    if !RUNNING.swap(true, Ordering::SeqCst) {
        let handle = unsafe {
            CreateThread(
                ptr::null_mut(),
                0,
                server_thread,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        if !handle.is_null() {
            THREAD_HANDLE.store(handle, Ordering::SeqCst);
            true
        } else {
            RUNNING.store(false, Ordering::SeqCst);
            file_log("[lumierre] CreateThread failed\n");
            false
        }
    } else {
        true
    }
}

pub fn stop_server() {
    if !RUNNING.swap(false, Ordering::SeqCst) {
        return;
    }
    if let Ok(addr) = ADDR.parse::<SocketAddr>() {
        let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    }
    let handle = THREAD_HANDLE.swap(ptr::null_mut(), Ordering::SeqCst);
    if !handle.is_null() {
        unsafe {
            WaitForSingleObject(handle, INFINITE);
            CloseHandle(handle);
        }
    }
}
