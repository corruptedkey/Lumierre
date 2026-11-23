# Lumierre: an offline validation proxy for Lumabar

**Lumierre provides in-process local validation and server emulation for Lumabar.** It loads alongside the desktop dock as a transparent multimedia proxy DLL (`winmm.dll`), redirecting validation requests to a lightweight local loopback service and signing payloads with Ed25519.

[What it is](#what-lumierre-is) · [How it works](#how-it-works) · [Supported versions](#supported-versions) · [Key generation](#key-generation) · [Building](#building-lumierre) · [Installation](#installation)

## What Lumierre is

Lumierre is an in-process proxy for Windows 10 and Windows 11. It sits in the application directory as `winmm.dll`. When `lumabar.exe` starts, Windows loads the library through standard search order. Lumierre transparently delegates genuine multimedia API calls to the operating system while serving validation queries locally.

- **Local validation service:** hosts an internal loopback server on `127.0.0.1:9712` that handles `/activate` and `/validate` requests.
- **Ed25519 cryptographic signing:** generates and verifies digital signatures matching the application's verification routine.
- **Dynamic request-echo engine:** mirrors request fields (`nonce`, `key`, `label`, `activation_id`) to satisfy application-side consistency checks.
- **Version guarding:** computes the SHA-256 digest of the host executable on launch. If an unsupported version is detected, it presents an informative system dialog and halts patching to prevent instability.
- **Transparent export proxying:** re-exports all required system routines (`PlaySoundW`, `timeGetTime`, `timeBeginPeriod`, `timeEndPeriod`) to `C:\Windows\System32\winmm.dll`.
- **Zero release overhead:** file logging and debugger outputs are fully compiled out in release builds.

## How it works

1. **Proxy Initialization:** On load (`DLL_PROCESS_ATTACH`), Lumierre verifies the calling executable name and calculates its SHA-256 checksum.
2. **Profile Matching:** The checksum is matched against the table of tested version profiles to resolve memory offsets (RVAs) for endpoint URLs and public keys.
3. **Memory Adjustment:** Page permissions are temporarily modified using `VirtualProtect` to point the target URL and signature public key to the local adapter.
4. **Loopback Service:** An embedded TCP server binds to `127.0.0.1:9712`. Incoming requests are parsed, structured, signed with the local private key, and returned.

## Supported versions

| Lumabar Version | Executable SHA-256 | Endpoint URL RVA | Public Key RVA |
| :--- | :--- | :--- | :--- |
| **1.2.28** | `484ce4e160a42a5883cee2c8f51d384a5922595846178fb2429455b689bc250f` | `0x135A47E` | `0x135A093` |
| **1.2.27** | `ef04fee14877329f8c1f351c8dea8de2ae50656e0915f5c4cc5560b21c5eeaab` | `0x13565BE` | `0x13561D3` |

If launched from an untested or updated build of `lumabar.exe`, Lumierre raises an alert dialog displaying the active file hash so new version offsets can be added.

## Key generation

Lumierre includes a built-in CLI utility to generate compatible Ed25519 keypairs:

```powershell
# Generate a new Ed25519 keypair
cargo run --bin keygen -- -keys
# or
cargo run --bin keygen -- --generate-keys
```

**Example Output:**
```text
Generated Ed25519 Keypair:
--------------------------
Private Key (base64): XMpLR8hCDgWxGA8VfGqhaxXLizB3UX3opp33eTLsKJc=
Public Key  (base64): lcFjCC1UkuS6SNzlfXd2IF8iXrSV9as4E/sst7Ye9UU=

Copy into src/consts.rs:
pub const PRIV_KEY_B64: &str = "XMpLR8hCDgWxGA8VfGqhaxXLizB3UX3opp33eTLsKJc=";
pub const PUB_KEY_B64: &str = "lcFjCC1UkuS6SNzlfXd2IF8iXrSV9as4E/sst7Ye9UU=";
```

> **Compile-Time Safety:** The library enforces that `PRIV_KEY` and `PUB_KEY` cannot be empty strings (`""`) at compile time.

## Building Lumierre

### Requirements
- Rust toolchain (`x86_64-pc-windows-msvc`, 2024 edition)
- Windows 10 or Windows 11

### Compilation
```powershell
cargo build --release
```

Outputs in `target\release\`:
- `winmm.dll` — The proxy dynamic link library.
- `keygen.exe` — Standalone key generation utility.

## Installation

1. Exit Lumabar if it's running.
2. Copy `winmm.dll` into the Lumabar folder
3. Start Lumabar.
4. Enter any license key in the settings dock.

## Architecture

```text
src/
├── consts.rs    # Server binding, keys, customer data, and default constants
├── keygen.rs    # Ed25519 keypair generator and output formatting
├── log.rs       # Conditional logging (active only in debug builds)
├── patch.rs     # VirtualProtect routines and memory RVA application
├── proxy.rs     # Dynamic forwarding to System32\winmm.dll
├── server.rs    # Local TCP server, JSON routing, and Ed25519 signing
├── version.rs   # Binary hash calculation and GUI alert dialogs
├── lib.rs       # DllMain lifecycle, version dispatch, and exports
└── main.rs      # CLI binary entrypoint for keygen
```

## License & Disclaimer

This project is intended for research, testing, and compatibility analysis. All product and service names belong to their respective owners.
