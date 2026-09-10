mod encryption;
use common::cli::{self, CipherApp, CipherFn, CipherMode, MacSpec};
use common::key::Key;
use encryption::gost28147_89::*;

const KEY: Key<8> = Key([1, 2, 3, 4, 5, 6, 7, 8]);
const BLOCK_SIZE: usize = 8;
const DEFAULT_MAC_BITS: usize = 32;
const ENCRYPTED_EXTENSION: &str = "gost";

fn cipher_fns(encryption_type: Gost28147_89Type) -> (CipherFn, CipherFn) {
    return match encryption_type {
        Gost28147_89Type::ECB => (Gost28147_89::encrypt_ecb, Gost28147_89::decrypt_ecb),
        Gost28147_89Type::CTR => (Gost28147_89::encrypt_ctr, Gost28147_89::decrypt_ctr),
        Gost28147_89Type::CFM => (Gost28147_89::encrypt_cfm, Gost28147_89::decrypt_cfm),
    };
}

/// ECB zero-pads the plaintext and appends the number of added bytes, so the
/// ciphertext is a whole number of blocks plus that one byte.
fn check_padded_blocks(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() <= BLOCK_SIZE || (bytes.len() - 1) % BLOCK_SIZE != 0 {
        return Err(format!(
            "expected whole {BLOCK_SIZE}-byte blocks plus one padding byte, got {} bytes",
            bytes.len()
        ));
    }

    let padding = bytes[bytes.len() - 1] as usize;
    if padding >= BLOCK_SIZE {
        return Err(format!(
            "invalid padding byte {padding}, expected less than {BLOCK_SIZE}"
        ));
    }

    return Ok(());
}

fn modes() -> Vec<CipherMode> {
    return [
        Gost28147_89Type::ECB,
        Gost28147_89Type::CTR,
        Gost28147_89Type::CFM,
    ]
    .into_iter()
    .map(|encryption_type| {
        let (encrypt, decrypt) = cipher_fns(encryption_type);
        let mode = CipherMode::new(encryption_type.to_string(), encrypt, decrypt);

        return match encryption_type {
            Gost28147_89Type::ECB => mode.checking_ciphertext(check_padded_blocks),
            // the gamma modes prepend the sync value and keep the length
            _ => mode.checking_ciphertext(cli::at_least(BLOCK_SIZE)),
        };
    })
    .collect();
}

fn main() {
    CipherApp {
        title: "GOST 28147-89",
        encrypted_extension: ENCRYPTED_EXTENSION,
        modes: modes(),
        mac: Some(MacSpec {
            compute: Gost28147_89::compute_mac,
            default_bits: DEFAULT_MAC_BITS,
            max_bits: MAX_MAC_BITS,
        }),
        digest: None,
        default_key: KEY,
    }
    .run();
}
