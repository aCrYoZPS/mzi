use num_bigint::{BigUint, RandBigInt};
use num_prime::nt_funcs::is_prime;
use rand::rngs::OsRng;
use rand::{SeedableRng, rngs::StdRng};

pub const REDUNDANCY_SIZE: usize = 16;

pub struct PublicKey {
    n: BigUint,
}

impl PublicKey {
    pub fn new(n: BigUint) -> Self {
        return Self { n };
    }

    pub fn n(&self) -> &BigUint {
        return &self.n;
    }
}

pub struct PrivateKey {
    public: PublicKey,
    p: BigUint,
    q: BigUint,
    yp: BigUint,
    yq: BigUint,
}

impl PrivateKey {
    pub fn new(p: BigUint, q: BigUint) -> Self {
        let big_two = BigUint::from(2u32);

        let yp = p.modpow(&(&q - &big_two), &q);
        let yq = q.modpow(&(&p - &big_two), &p);
        return Self {
            public: PublicKey { n: &p * &q },
            p,
            q,
            yp,
            yq,
        };
    }

    pub fn p(&self) -> &BigUint {
        return &self.p;
    }

    pub fn q(&self) -> &BigUint {
        return &self.q;
    }
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

    fn get_k_from_key(key: &PublicKey) -> usize {
        return key.n.bits().div_ceil(8) as usize;
    }

    pub fn keygen() -> (PrivateKey, PublicKey) {
        let p = Self::gen_prime_3mod4(1536);
        let mut q = Self::gen_prime_3mod4(1536);
        while q == p {
            q = Self::gen_prime_3mod4(1536);
        }
        let n = &p * &q;

        return (PrivateKey::new(p, q), PublicKey::new(n));
    }

    fn encrypt_block(block: &[u8], key: &PublicKey) -> Vec<u8> {
        let block_size: usize = Self::get_k_from_key(key) - 1;
        let mut m_bytes = vec![0u8; block_size];
        m_bytes[..block.len()].copy_from_slice(block);
        m_bytes.copy_within((block.len() - REDUNDANCY_SIZE)..block.len(), block.len());
        m_bytes[block_size - 1] = 0x01;

        let m = BigUint::from_bytes_le(&m_bytes);
        let c = m.modpow(&BigUint::from(2u32), &key.n);

        let mut res = c.to_bytes_le();
        res.resize(block_size + 1, 0);

        return res;
    }

    fn decrypt_block(block: &[u8], key: &PrivateKey) -> Result<Vec<u8>, String> {
        let block_size: usize = Self::get_k_from_key(&key.public);
        let mut c_bytes = vec![0u8; block_size];
        c_bytes.copy_from_slice(block);

        let mut results: Vec<BigUint> = Vec::with_capacity(4);

        let big_one = BigUint::from(1u32);
        let big_four = BigUint::from(4u32);
        let c = BigUint::from_bytes_le(&c_bytes);
        let p = &key.p;
        let q = &key.q;
        let n = &key.public.n;

        let mp = c.modpow(&((p + &big_one) / &big_four), p);
        let mq = c.modpow(&((q + &big_one) / &big_four), q);

        let yp = &key.yp;
        let yq = &key.yq;

        let t1 = yp * p * &mq;
        let t2 = yq * q * &mp;

        results.push((&t1 + &t2) % n);
        results.push(n - &results[0]);
        results.push(((&t1 % n) + n - (&t2 % n)) % n);
        results.push(n - &results[2]);

        for result in results {
            let redundancy_start = block_size - 2 - REDUNDANCY_SIZE;
            let possible_copy_start = redundancy_start - REDUNDANCY_SIZE;
            let mut res_bytes = result.to_bytes_le();
            if res_bytes.len() != block_size - 1 {
                continue;
            } else if res_bytes[block_size - 2] != 0x01 {
                continue;
            } else if res_bytes[possible_copy_start..redundancy_start]
                == res_bytes[redundancy_start..(block_size - 2)]
            {
                res_bytes.truncate(redundancy_start);
                return Ok(res_bytes);
            }
        }

        return Err("Block corrupted".to_owned());
    }

    pub fn encrypt(mut plain_bytes: Vec<u8>, key: &PublicKey) -> Vec<u8> {
        let block_size: usize = Self::get_k_from_key(key) - 1;
        let payload_size = block_size - REDUNDANCY_SIZE as usize - 1;

        let mut result: Vec<u8> = vec![];

        let padding = payload_size - plain_bytes.len() % payload_size;
        plain_bytes.push(0x80);
        for _ in 0..(padding - 1) {
            plain_bytes.push(0);
        }

        let blocks = plain_bytes.chunks(payload_size);
        for block in blocks {
            result.extend_from_slice(&Self::encrypt_block(block, key));
        }

        return result;
    }

    pub fn decrypt(encrypted_bytes: Vec<u8>, key: &PrivateKey) -> Result<Vec<u8>, String> {
        let block_size = Self::get_k_from_key(&key.public);
        if encrypted_bytes.is_empty() || encrypted_bytes.len() % block_size != 0 {
            return Err("Invalid message length".to_owned());
        }

        let mut result: Vec<u8> = vec![];

        let blocks = encrypted_bytes.chunks(block_size);
        for block in blocks {
            let decrypted = Self::decrypt_block(block, key)?;
            result.extend_from_slice(&decrypted);
        }

        let payload_size = block_size - 2 - REDUNDANCY_SIZE;
        match result.iter().rposition(|&b| b != 0) {
            Some(pos) if result[pos] == 0x80 && pos >= result.len() - payload_size => {
                result.truncate(pos);
            }
            _ => return Err("Invalid padding".to_owned()),
        }

        return Ok(result);
    }
}
