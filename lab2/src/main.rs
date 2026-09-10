mod encryption;
use common::cli::{self, CipherApp, CipherFn, CipherMode, DigestSpec, MacSpec};
use common::key::Key;
use encryption::bel_t::*;

const KEY: Key<8> = Key([1, 2, 3, 4, 5, 6, 7, 8]);
const BLOCK_SIZE: usize = 16;
const DEFAULT_MAC_BITS: usize = 64;
const ENCRYPTED_EXTENSION: &str = "belt";

fn cipher_fns(encryption_type: BelTType) -> (CipherFn, CipherFn) {
    return match encryption_type {
        BelTType::ECB => (BelT::encrypt_ecb, BelT::decrypt_ecb),
        BelTType::CBC => (BelT::encrypt_cbc, BelT::decrypt_cbc),
        BelTType::CTR => (BelT::encrypt_ctr, BelT::decrypt_ctr),
        BelTType::CFM => (BelT::encrypt_cfm, BelT::decrypt_cfm),
    };
}

fn modes() -> Vec<CipherMode> {
    return [BelTType::ECB, BelTType::CBC, BelTType::CTR, BelTType::CFM]
        .into_iter()
        .map(|encryption_type| {
            let (encrypt, decrypt) = cipher_fns(encryption_type);
            let mode = CipherMode::new(encryption_type.to_string(), encrypt, decrypt);

            return match encryption_type {
                // ciphertext stealing has nothing to steal from below one block
                BelTType::ECB => mode
                    .checking_plaintext(cli::at_least(BLOCK_SIZE))
                    .checking_ciphertext(cli::at_least(BLOCK_SIZE)),
                // ... and CBC carries the sync value in front of it
                BelTType::CBC => mode
                    .checking_plaintext(cli::at_least(BLOCK_SIZE))
                    .checking_ciphertext(cli::at_least(2 * BLOCK_SIZE)),
                // the gamma modes keep the length, only the sync value is added
                _ => mode.checking_ciphertext(cli::at_least(BLOCK_SIZE)),
            };
        })
        .collect();
}

fn main() {
    CipherApp {
        title: "BelT (STB 34.101.31-2011)",
        encrypted_extension: ENCRYPTED_EXTENSION,
        modes: modes(),
        mac: Some(MacSpec {
            compute: BelT::compute_mac,
            default_bits: DEFAULT_MAC_BITS,
            max_bits: MAX_MAC_BITS,
        }),
        digest: Some(DigestSpec {
            name: "hash",
            compute: BelT::hash,
        }),
        default_key: KEY,
    }
    .run();
}
