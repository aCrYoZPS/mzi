use std::ops::Div;

use num_bigint::{BigUint, RandBigInt};
use num_prime::nt_funcs::is_prime;
use rand::rngs::OsRng;
use rand::{SeedableRng, rngs::StdRng};

const BLOCK_SIZE: usize = 16;
const REDUNDANCY_SIZE: usize = 16;

type RabinPublicKey = BigUint;
type RabinPrivateKey = (BigUint, BigUint);

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

    pub fn keygen() -> (RabinPrivateKey, RabinPublicKey) {
        let p = Self::gen_prime_3mod4(1536);
        let mut q = Self::gen_prime_3mod4(1536);
        while q == p {
            q = Self::gen_prime_3mod4(1536);
        }
        let n = &p * &q;

        return ((p, q), n);
    }

    fn add_redundancy(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.resize(len.bytes(), 0);
        return bytes;
    }

    fn check_redundancy(bytes: &Vec<u8>) -> bool {
        todo!()
    }

    fn egcd(a: &BigUint, b: &BigUint) -> (BigUint, BigUint, BigUint) {
        if *b == BigUint::from(0u32) {
            return (a.clone(), BigUint::from(1u32), BigUint::from(0u32));
        }

        let (g, x1, y1) = Self::egcd(b, &(a % b));

        return (g, y1.clone(), x1 - (a / b) * y1);
    }

    fn encrypt_block(block: &[u8], key: &RabinPublicKey) -> Vec<u8> {
        let m = BigUint::from_bytes_le(block);
        let c = m.modpow(&BigUint::from(2u32), key);

        return c.to_bytes_le();
    }

    fn decrypt_block(block: &[u8], key: &RabinPrivateKey) -> Option<[Vec<u8>; 4]> {
        let c = BigUint::from_bytes_le(block);
        let p = &key.0;
        let q = &key.1;
        let n = p * q;

        let mp = c.modpow((p + 1) / 4, p);
        let mq = c.modpow((q + 1) / 4, q);

        let (g, yp, yq) = Self::egcd(p, q);

        if g != BigUint::from(1u32) {
            return None;
        }

        let r1 = (yp * p * mq + yq * q * mp) % n;
        let r2 = n - r1;
        let r3 = (yp * p * mq + yq * q * mp) % n;
        let r4 = n - r3;

        return Some([
            r1.to_bytes_le(),
            r2.to_bytes_le(),
            r3.to_bytes_le(),
            r4.to_bytes_le(),
        ]);
    }

    pub fn encrypt(mut plain_bytes: Vec<u8>, key: &RabinPublicKey) -> Vec<u8> {
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
            result.extend_from_slice(&Self::encrypt_block(block, key));
        }

        result.push(padding as u8);

        return Self::add_redundancy(result);
    }

    fn decrypt(mut encrypted_bytes: Vec<u8>, key: &RabinPrivateKey) -> [Vec<u8>; 4] {
        let mut results: [Vec<u8>; 4] = [vec![], vec![], vec![], vec![]];

        let padding = encrypted_bytes.pop().unwrap_or(0) as usize;

        let blocks = encrypted_bytes.chunks(BLOCK_SIZE);
        for block in blocks {
            let m = BigUint::from_bytes_le(block);
            let c = m.modpow(&BigUint::from(2u32), &key.n);
            result.extend_from_slice(&c.to_bytes_le());
        }

        for _ in 0..padding {
            result.pop();
        }

        todo!()
    }
}
