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

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> StdRng {
        return StdRng::seed_from_u64(4);
    }

    #[test]
    fn keys_fit_together() {
        let mut rng = rng();
        let (private, public) = McEliece::keygen_with_rng(Params::SMALL, &mut rng).unwrap();
        let code = private.code();
        assert_eq!(
            (public.n(), public.k(), public.t()),
            (code.n(), code.k(), code.t())
        );

        let s = private.s_inv().inverse().unwrap();
        let p = private.p_inv().inverse();
        assert_eq!(
            public.matrix(),
            &s.mul(code.generator()).permute_columns(&p)
        );

        assert_ne!(
            public.matrix().columns(0..public.k()),
            Matrix::identity(public.k())
        );
    }

    #[test]
    fn block_round_trip() {
        let mut rng = rng();
        for params in [Params::TOY, Params::SMALL, Params::ORIGINAL] {
            let (private, public) = McEliece::keygen_with_rng(params, &mut rng).unwrap();
            for _ in 0..20 {
                let message = BitVec::random(public.k(), &mut rng);
                let cipher = McEliece::encrypt_block(&message, &public, &mut rng);
                assert_eq!(cipher.len(), public.n());
                assert_eq!(McEliece::decrypt_block(&cipher, &private).unwrap(), message);
            }
        }
    }

    #[test]
    fn error_vector_has_weight_t() {
        let mut rng = rng();
        let (_, public) = McEliece::keygen_with_rng(Params::SMALL, &mut rng).unwrap();
        let zero = BitVec::zeros(public.k());
        for _ in 0..20 {
            assert_eq!(
                McEliece::encrypt_block(&zero, &public, &mut rng).weight(),
                public.t()
            );
        }
    }

    #[test]
    fn bytes_round_trip() {
        let mut rng = rng();
        for params in [Params::TOY, Params::SMALL] {
            let (private, public) = McEliece::keygen_with_rng(params, &mut rng).unwrap();
            let k = public.k();
            for len in [0, 1, 2, 3, k / 8, k / 8 + 1, 2 * k / 8, 100, 257] {
                let plain: Vec<u8> = (0..len).map(|_| rng.r#gen()).collect();
                let cipher = McEliece::encrypt_with_rng(plain.clone(), &public, &mut rng);
                let blocks = (len * 8) / k + 1;
                assert_eq!(cipher.len(), blocks * public.n().div_ceil(8));
                assert_eq!(McEliece::decrypt(cipher, &private).unwrap(), plain);
            }
        }
    }

    #[test]
    fn original_parameters_round_trip() {
        let mut rng = rng();
        let (private, public) = McEliece::keygen_with_rng(Params::ORIGINAL, &mut rng).unwrap();
        let plain = "Криптосистема Мак-Элиса, 1978".as_bytes().to_vec();
        let cipher = McEliece::encrypt(plain.clone(), &public);
        assert_eq!(McEliece::decrypt(cipher, &private).unwrap(), plain);
    }

    #[test]
    fn encryption_is_randomized() {
        let mut rng = rng();
        let (private, public) = McEliece::keygen_with_rng(Params::SMALL, &mut rng).unwrap();
        let plain = b"same text".to_vec();
        let first = McEliece::encrypt_with_rng(plain.clone(), &public, &mut rng);
        let second = McEliece::encrypt_with_rng(plain.clone(), &public, &mut rng);
        assert_ne!(first, second);
        assert_eq!(McEliece::decrypt(first, &private).unwrap(), plain);
        assert_eq!(McEliece::decrypt(second, &private).unwrap(), plain);
    }

    #[test]
    fn rejects_malformed_ciphertexts() {
        let mut rng = rng();
        let (private, public) = McEliece::keygen_with_rng(Params::SMALL, &mut rng).unwrap();
        let cipher = McEliece::encrypt_with_rng(b"hello".to_vec(), &public, &mut rng);

        assert!(McEliece::decrypt(vec![], &private).is_err());
        assert!(McEliece::decrypt(cipher[1..].to_vec(), &private).is_err());

        let zero_block = McEliece::encrypt_block(&BitVec::zeros(public.k()), &public, &mut rng);
        assert!(McEliece::decrypt(zero_block.to_bytes(), &private).is_err());

        let (other, _) = McEliece::keygen_with_rng(Params::SMALL, &mut rng).unwrap();
        assert_ne!(
            McEliece::decrypt(cipher, &other).ok(),
            Some(b"hello".to_vec())
        );
    }

    #[test]
    fn rejects_bits_past_n() {
        let mut rng = rng();
        let params = Params { m: 5, n: 30, t: 3 };
        let (private, public) = McEliece::keygen_with_rng(params, &mut rng).unwrap();
        let mut cipher = McEliece::encrypt_with_rng(b"x".to_vec(), &public, &mut rng);
        assert_eq!(McEliece::decrypt(cipher.clone(), &private).unwrap(), b"x");
        cipher[3] |= 0x80;
        assert!(McEliece::decrypt(cipher, &private).is_err());
    }

    #[test]
    fn one_flipped_bit_is_fatal_or_absorbed() {
        let mut rng = rng();
        let (private, public) = McEliece::keygen_with_rng(Params::TOY, &mut rng).unwrap();
        let message = BitVec::random(public.k(), &mut rng);
        let cipher = McEliece::encrypt_block(&message, &public, &mut rng);
        let error_positions: Vec<usize> = cipher
            .xor(&public.matrix().vec_mul(&message))
            .iter_ones()
            .collect();

        for i in 0..public.n() {
            let mut tampered = cipher.clone();
            tampered.flip(i);
            let result = McEliece::decrypt_block(&tampered, &private);
            if error_positions.contains(&i) {
                assert_eq!(result.unwrap(), message);
            } else {
                assert_ne!(result.ok(), Some(message.clone()));
            }
        }
    }
}
