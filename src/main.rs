mod consts;
mod keygen;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let has_key_flag = args
        .iter()
        .any(|arg| arg == "-keys" || arg == "--generate-keys");

    if has_key_flag {
        let (priv_b64, pub_b64) = keygen::generate_keypair();
        print!("{}", keygen::format_keypair_output(&priv_b64, &pub_b64));
    } else {
        println!("Usage:\n  keygen [OPTIONS]\n");
        println!("Options:");
        println!("  -keys, --generate-keys    Generate a new Ed25519 keypair for license signing");
        println!("  -h, --help                Show this help message\n");
        println!("Current Active Keys in src/consts.rs:");
        println!("  Private Key: {}", consts::PRIV_KEY_B64);
        println!("  Public Key:  {}\n", consts::PUB_KEY_B64);
    }
}
