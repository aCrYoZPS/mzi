use num_bigint::{BigUint, RandBigInt};
use num_prime::nt_funcs::is_prime;
use rand::rngs::OsRng;
use rand::{SeedableRng, rngs::StdRng};

const BLOCK_SIZE: usize = 16;

pub struct RabinKey {
    p: BigUint,
    q: BigUint,
    n: BigUint,
}

pub struct RabinPrivateKey {
    n: BigUint,
}

pub struct Rabin {}

impl Rabin {
    fn gen_prime_3mod4(bits: u64) -> BigUint {
        let mut rng = StdRng::from_rng(&mut OsRng).unwrap();
        loop {
            let mut candidate = rng.gen_biguint(bits);
            candidate.set_bit(bits - 1, true);
            candidate.set_bit(1, true);
            candidate.set_bit(0, true);

            if is_prime(&candidate, None).probably() {
                return candidate;
            }
        }
    }

    pub fn encrypt(mut plain_bytes: Vec<u8>, key: &RabinKey) -> Vec<u8> {
        // let p = Self::gen_prime_3mod4(1536);
        // let mut q = Self::gen_prime_3mod4(1536);
        // while q == p {
        //     q = Self::gen_prime_3mod4(1536);
        // }
        // let n = &p * &q;
        //

        let padding = {
            let pd = BLOCK_SIZE - plain_bytes.len() % BLOCK_SIZE;
            if pd == BLOCK_SIZE { 0 } else { pd }
        };

        for _ in 0..padding {
            plain_bytes.push(0);
        }

        let mut result: Vec<u8> = vec![];

        let blocks = plain_bytes.chunks(BLOCK_SIZE);
        for block in blocks {
            let m = BigUint::from_bytes_le(block);
            let c = m.modpow(&BigUint::from(2u32), &key.n);
            result.extend_from_slice(&c.to_bytes_le());
        }

        result.push(padding as u8);

        return result;
    }
}
