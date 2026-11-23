use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

pub fn generate_keypair() -> (String, String) {
    let mut csprng = OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pk = sk.verifying_key();
    let priv_b64 = B64.encode(sk.to_bytes());
    let pub_b64 = B64.encode(pk.to_bytes());
    (priv_b64, pub_b64)
}

pub fn format_keypair_output(priv_b64: &str, pub_b64: &str) -> String {
    format!(
        "Generated Ed25519 Keypair:\n\
         --------------------------\n\
         Private Key (base64): {}\n\
         Public Key  (base64): {}\n\n\
         Copy into src/consts.rs:\n\
         pub const PRIV_KEY_B64: &str = \"{}\";\n\
         pub const PUB_KEY_B64: &str = \"{}\";\n",
        priv_b64, pub_b64, priv_b64, pub_b64
    )
}
