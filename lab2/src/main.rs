mod encryption;
use common::cli::{self, CheckFn, CipherApp, CipherFn, CipherMode};
use common::key::Key;
use encryption::bel_t::*;

const KEY: Key<8> = Key([1, 2, 3, 4, 5, 6, 7, 8]);
const BLOCK_SIZE: usize = 16;
const ENCRYPTED_EXTENSION: &str = "belt";

fn cipher_fns(encryption_type: BelTType) -> (CipherFn, CipherFn) {
    return match encryption_type {
        BelTType::ECB => (BelT::encrypt_ecb, BelT::decrypt_ecb),
        BelTType::CTR => (BelT::encrypt_ctr, BelT::decrypt_ctr),
        BelTType::CFM => (BelT::encrypt_cfm, BelT::decrypt_cfm),
    };
}

fn check_ecb(bytes: &[u8], mode: &str) -> Result<(), String> {
    return cli::check_ecb_padding(bytes, mode, BLOCK_SIZE);
}

fn check_sync(bytes: &[u8], mode: &str) -> Result<(), String> {
    return cli::check_sync_prefix(bytes, mode, BLOCK_SIZE);
}

fn modes() -> Vec<CipherMode> {
    return [BelTType::ECB, BelTType::CTR, BelTType::CFM]
        .into_iter()
        .map(|encryption_type| {
            let (encrypt, decrypt) = cipher_fns(encryption_type);

            CipherMode {
                name: encryption_type.to_string(),
                encrypt,
                decrypt,
                check_ciphertext: Some(if encryption_type == BelTType::ECB {
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
        title: "BelT (STB 34.101.31-2011)",
        encrypted_extension: ENCRYPTED_EXTENSION,
        modes: modes(),
        mac: None,
        default_key: KEY,
    }
    .run();
}
