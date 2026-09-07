mod encryption;
use common::cli::{self, CheckFn, CipherApp, CipherFn, CipherMode, MacSpec};
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

fn check_ecb(bytes: &[u8], mode: &str) -> Result<(), String> {
    return cli::check_ecb_padding(bytes, mode, BLOCK_SIZE);
}

fn check_sync(bytes: &[u8], mode: &str) -> Result<(), String> {
    return cli::check_sync_prefix(bytes, mode, BLOCK_SIZE);
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

        CipherMode {
            name: encryption_type.to_string(),
            encrypt,
            decrypt,
            check_ciphertext: Some(if encryption_type == Gost28147_89Type::ECB {
                check_ecb as CheckFn
            } else {
                check_sync as CheckFn
            }),
        }
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
        default_key: KEY,
    }
    .run();
}
