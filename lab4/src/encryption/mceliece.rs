use super::goppa::Goppa;
use super::matrix::{BitVec, Matrix, Permutation};
use rand::rngs::OsRng;
use rand::{Rng, SeedableRng, rngs::StdRng};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub m: u32,
    pub n: usize,
    pub t: usize,
}

impl Params {
    pub const TOY: Params = Params { m: 4, n: 16, t: 2 };
    pub const SMALL: Params = Params { m: 8, n: 256, t: 8 };
    pub const ORIGINAL: Params = Params {
        m: 10,
        n: 1024,
        t: 50,
    };
}

#[derive(Clone)]
pub struct PublicKey {
    matrix: Matrix,
    t: usize,
}

impl PublicKey {
    pub fn matrix(&self) -> &Matrix {
        return &self.matrix;
    }

    pub fn n(&self) -> usize {
        return self.matrix.col_count();
    }

    pub fn k(&self) -> usize {
        return self.matrix.row_count();
    }

    pub fn t(&self) -> usize {
        return self.t;
    }

    fn block_bytes(&self) -> usize {
        return self.n().div_ceil(8);
    }
}

pub struct PrivateKey {
    public: PublicKey,
    code: Goppa,
    s_inv: Matrix,
    p_inv: Permutation,
}

impl PrivateKey {
    pub fn public(&self) -> &PublicKey {
        return &self.public;
    }

    pub fn code(&self) -> &Goppa {
        return &self.code;
    }

    pub fn s_inv(&self) -> &Matrix {
        return &self.s_inv;
    }

    pub fn p_inv(&self) -> &Permutation {
        return &self.p_inv;
    }
}

pub struct McEliece {}

impl McEliece {
    pub fn keygen(params: Params) -> Result<(PrivateKey, PublicKey), String> {
        let mut rng = StdRng::from_rng(&mut OsRng).unwrap();

        return Self::keygen_with_rng(params, &mut rng);
    }

    pub fn keygen_with_rng<R: Rng>(
        params: Params,
        rng: &mut R,
    ) -> Result<(PrivateKey, PublicKey), String> {
        let code = Goppa::generate(params.m, params.n, params.t, rng)?;
        let (s, s_inv) = Matrix::random_invertible(code.k(), rng);
        let p = Permutation::random(code.n(), rng);

        let public = PublicKey {
            matrix: s.mul(code.generator()).permute_columns(&p),
            t: code.t(),
        };
        let private = PrivateKey {
            public: public.clone(),
            code,
            s_inv,
            p_inv: p.inverse(),
        };

        return Ok((private, public));
    }

    pub fn encrypt_block<R: Rng>(message: &BitVec, key: &PublicKey, rng: &mut R) -> BitVec {
        let e = BitVec::random_with_weight(key.n(), key.t(), rng);

        return key.matrix.vec_mul(message).xor(&e);
    }

    pub fn decrypt_block(cipher: &BitVec, key: &PrivateKey) -> Result<BitVec, String> {
        let codeword = key.code.decode(&key.p_inv.apply(cipher))?;
        let message_s = key.code.message(&codeword);

        return Ok(key.s_inv.vec_mul(&message_s));
    }

    pub fn encrypt(plain_bytes: Vec<u8>, key: &PublicKey) -> Vec<u8> {
        let mut rng = StdRng::from_rng(&mut OsRng).unwrap();

        return Self::encrypt_with_rng(plain_bytes, key, &mut rng);
    }

    pub fn encrypt_with_rng<R: Rng>(plain_bytes: Vec<u8>, key: &PublicKey, rng: &mut R) -> Vec<u8> {
        let k = key.k();
        let data_len = plain_bytes.len() * 8;
        let blocks = data_len / k + 1;

        let data = BitVec::from_bytes(&plain_bytes, data_len).unwrap();
        let mut padded = BitVec::zeros(blocks * k);
        for i in data.iter_ones() {
            padded.set(i, true);
        }
        padded.set(data_len, true);

        let mut result = Vec::with_capacity(blocks * key.block_bytes());
        for b in 0..blocks {
            let message = padded.slice(b * k..(b + 1) * k);
            result.extend(Self::encrypt_block(&message, key, rng).to_bytes());
        }

        return result;
    }

    pub fn decrypt(encrypted_bytes: Vec<u8>, key: &PrivateKey) -> Result<Vec<u8>, String> {
        let (n, k) = (key.public.n(), key.public.k());
        let block_bytes = key.public.block_bytes();
        if encrypted_bytes.is_empty() || !encrypted_bytes.len().is_multiple_of(block_bytes) {
            return Err("Invalid message length".to_owned());
        }

        let blocks = encrypted_bytes.len() / block_bytes;
        let mut padded = BitVec::zeros(blocks * k);
        for (b, chunk) in encrypted_bytes.chunks(block_bytes).enumerate() {
            let cipher = BitVec::from_bytes(chunk, n).map_err(|_| "Block corrupted".to_owned())?;
            let message =
                Self::decrypt_block(&cipher, key).map_err(|_| "Block corrupted".to_owned())?;
            for i in message.iter_ones() {
                padded.set(b * k + i, true);
            }
        }

        match padded.last_one() {
            Some(pos) if pos.is_multiple_of(8) && pos + k >= padded.len() => {
                return Ok(padded.prefix(pos).to_bytes());
            }
            _ => return Err("Invalid padding".to_owned()),
        }
    }
}
