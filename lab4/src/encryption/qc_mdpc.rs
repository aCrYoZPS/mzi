use super::bit_vecs::{DenseBitVec, SparseBitVec};
use rand::{
    Rng, SeedableRng,
    rngs::{OsRng, StdRng},
    seq::index::sample,
};

pub struct QcMdpcParams {
    r: usize,
    d: usize,
    t: usize,
}

pub const CRYPTO_PARAMS: QcMdpcParams = QcMdpcParams {
    r: 12323,
    d: 71,
    t: 134,
};

const MAX_ITERATIONS: usize = 10;

#[derive(Clone)]
pub struct PublicKey {
    r: usize,
    t: usize,
    a: DenseBitVec,
    b: DenseBitVec,
}

impl QcMdpcParams {
    pub fn r(&self) -> usize {
        return self.r;
    }

    pub fn d(&self) -> usize {
        return self.d;
    }

    pub fn t(&self) -> usize {
        return self.t;
    }
}

impl PublicKey {
    pub fn r(&self) -> usize {
        return self.r;
    }

    pub fn t(&self) -> usize {
        return self.t;
    }

    pub fn a(&self) -> &DenseBitVec {
        return &self.a;
    }

    pub fn b(&self) -> &DenseBitVec {
        return &self.b;
    }
}

pub struct PrivateKey {
    h0: SparseBitVec,
    h1: SparseBitVec,
    a_inv: DenseBitVec,
    public: PublicKey,
}

impl PrivateKey {
    pub fn h0(&self) -> &SparseBitVec {
        return &self.h0;
    }

    pub fn h1(&self) -> &SparseBitVec {
        return &self.h1;
    }

    pub fn a_inv(&self) -> &DenseBitVec {
        return &self.a_inv;
    }
}

pub struct QcMdpc {}

impl QcMdpc {
    pub fn keygen(params: QcMdpcParams) -> (PrivateKey, PublicKey) {
        let mut rng = StdRng::from_rng(&mut OsRng).unwrap();

        let h0 = SparseBitVec::random(params.r, params.d, &mut rng);
        let h1 = SparseBitVec::random(params.r, params.d, &mut rng);
        let h1_inv = DenseBitVec::from(&h1)
            .inverse()
            .expect("h1 of odd weight d is invertible");
        let q = h0.mul(&h1_inv);

        let a = DenseBitVec::random_odd(params.r, &mut rng);
        let a_inv = a
            .inverse()
            .expect("a of odd weight other than all ones is invertible");
        let b = a.mul(&q);

        let pub_key = PublicKey {
            r: params.r,
            t: params.t,
            a,
            b,
        };

        return (
            PrivateKey {
                h0,
                h1,
                a_inv,
                public: pub_key.clone(),
            },
            pub_key,
        );
    }

    pub fn encrypt_block<R: Rng>(
        block: &[u8],
        key: &PublicKey,
        rng: &mut R,
    ) -> (DenseBitVec, DenseBitVec) {
        let m = DenseBitVec::from_bytes(key.r, block);

        let (low, high): (Vec<usize>, Vec<usize>) = sample(rng, 2 * key.r, key.t)
            .into_iter()
            .partition(|&p| p < key.r);
        let e0 = SparseBitVec::from_positions(key.r, low);
        let e1 = SparseBitVec::from_positions(key.r, high.into_iter().map(|p| p - key.r).collect());

        let mut c0 = m.mul(&key.a);
        c0.xor_sparse_assign(&e0);

        let mut c1 = m.mul(&key.b);
        c1.xor_sparse_assign(&e1);

        return (c0, c1);
    }

    pub fn encrypt(plain_bytes: &[u8], key: &PublicKey) -> Vec<u8> {
        let mut rng = StdRng::from_rng(&mut OsRng).unwrap();

        let k = key.r / 8;
        let mut bytes = Vec::from(plain_bytes);
        let mut result = vec![];

        bytes.push(1);

        let padding = (k - (bytes.len() % k)) % k;
        bytes.resize(bytes.len() + padding, 0);

        for block in bytes.chunks(k) {
            let (c0, c1) = Self::encrypt_block(block, key, &mut rng);

            result.extend_from_slice(&c0.to_bytes());
            result.extend_from_slice(&c1.to_bytes());
        }

        return result;
    }

    fn counters(s: &DenseBitVec, h: &SparseBitVec) -> Vec<usize> {
        let r = s.r();
        return (0..r)
            .map(|j| {
                h.positions()
                    .iter()
                    .filter(|&&p| s.get((j + p) % r))
                    .count()
            })
            .collect();
    }

    fn threshold(s: &DenseBitVec) -> usize {
        return ((0.0069722 * s.weight() as f64 + 13.530).floor() as usize).max(36);
    }

    pub fn decode(s: &mut DenseBitVec, key: &PrivateKey) -> Option<(DenseBitVec, DenseBitVec)> {
        let r = key.public.r;
        let t = key.public.t;
        let h0 = &key.h0;
        let h1 = &key.h1;

        let mut e0 = DenseBitVec::zero(r);
        let mut e1 = DenseBitVec::zero(r);

        for _ in 0..MAX_ITERATIONS {
            if s.is_zero() {
                break;
            }

            let mut flipped = false;

            let upc0 = Self::counters(&s, h0);
            let upc1 = Self::counters(&s, h1);
            let t_flip = Self::threshold(&s);

            for j in 0..r {
                if upc0[j] >= t_flip {
                    e0.flip(j);
                    flipped = true;
                    for &p in h0.positions() {
                        s.flip((j + p) % r);
                    }
                }
                if upc1[j] >= t_flip {
                    e1.flip(j);
                    flipped = true;
                    for &p in h1.positions() {
                        s.flip((j + p) % r);
                    }
                }
            }

            if !flipped {
                return None;
            }
        }

        if !s.is_zero() || e0.weight() + e1.weight() != t {
            return None;
        }

        return Some((e0, e1));
    }

    pub fn decrypt(encrypted_bytes: &[u8], key: &PrivateKey) -> Option<Vec<u8>> {
        let r = key.public.r;

        let k = r / 8;
        let mut result = vec![];

        let half = r.div_ceil(8);
        if encrypted_bytes.len() % (2 * half) != 0 {
            return None;
        }

        for (c0_bytes, c1_bytes) in encrypted_bytes
            .chunks(2 * half)
            .map(|block| block.split_at(half))
        {
            let mut c0 = DenseBitVec::from_bytes(r, c0_bytes);
            let mut c1 = DenseBitVec::from_bytes(r, c1_bytes);
            let mut s = key.h0.mul(&c0).xor(&key.h1.mul(&c1));

            let (e0, e1) = Self::decode(&mut s, key)?;

            c0.xor_assign(&e0);
            let m = c0.mul(&key.a_inv);

            c1.xor_assign(&e1);
            if c1 != m.mul(&key.public.b) {
                return None;
            }

            result.extend_from_slice(&m.to_bytes()[..k]);
        }

        while result.last() == Some(&0) {
            result.pop();
        }
        if result.pop() != Some(1) {
            return None;
        }

        return Some(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> StdRng {
        return StdRng::seed_from_u64(4);
    }

    fn random_bytes<R: Rng>(len: usize, rng: &mut R) -> Vec<u8> {
        return (0..len).map(|_| rng.gen_range(0..=u8::MAX)).collect();
    }

    #[test]
    fn keys_satisfy_h1_q_eq_h0() {
        let (private, public) = QcMdpc::keygen(CRYPTO_PARAMS);
        // B = a q, поэтому q = a^(-1) B
        let q = private.a_inv.mul(&public.b);
        assert_eq!(private.h1.mul(&q), DenseBitVec::from(&private.h0));
        assert_eq!(public.a.mul(&private.a_inv), DenseBitVec::one(public.r));
    }

    #[test]
    fn syndrome_depends_only_on_errors() {
        let (private, public) = QcMdpc::keygen(CRYPTO_PARAMS);
        let mut rng = rng();
        let block = random_bytes(public.r / 8, &mut rng);
        let m = DenseBitVec::from_bytes(public.r, &block);

        let (c0, c1) = QcMdpc::encrypt_block(&block, &public, &mut rng);
        let e0 = c0.xor(&m.mul(&public.a));
        let e1 = c1.xor(&m.mul(&public.b));
        assert_eq!(e0.weight() + e1.weight(), public.t);

        let s = private.h0.mul(&c0).xor(&private.h1.mul(&c1));
        let expected = e0
            .mul(&DenseBitVec::from(&private.h0))
            .xor(&e1.mul(&DenseBitVec::from(&private.h1)));
        assert_eq!(s, expected);
    }

    #[test]
    fn roundtrip_messages() {
        let (private, public) = QcMdpc::keygen(CRYPTO_PARAMS);
        let mut rng = rng();
        let k = public.r / 8;
        let half = public.r.div_ceil(8);

        let mut messages = vec![
            vec![],
            b"a".to_vec(),
            "Шифр McEliece на кодах QC-MDPC".as_bytes().to_vec(),
            vec![0; 10],
            vec![1; 5],
        ];
        for len in [k - 1, k, k + 1, 2 * k, 3 * k + 17] {
            messages.push(random_bytes(len, &mut rng));
        }

        for message in &messages {
            let encrypted = QcMdpc::encrypt(message, &public);
            // дополнение всегда есть: len + 1 байт, округлённые вверх до блоков по k
            let blocks = (message.len() + 1).div_ceil(k);
            assert_eq!(encrypted.len(), blocks * 2 * half, "len = {}", message.len());
            assert_eq!(
                QcMdpc::decrypt(&encrypted, &private).as_ref(),
                Some(message),
                "len = {}",
                message.len()
            );
        }
    }

    #[test]
    fn many_blocks_without_failures() {
        let (private, public) = QcMdpc::keygen(CRYPTO_PARAMS);
        let mut rng = rng();
        let message = random_bytes(50 * (public.r / 8) - 1, &mut rng);
        let encrypted = QcMdpc::encrypt(&message, &public);
        assert_eq!(QcMdpc::decrypt(&encrypted, &private), Some(message));
    }

    #[test]
    fn rejects_malformed_ciphertext() {
        let (private, public) = QcMdpc::keygen(CRYPTO_PARAMS);
        assert_eq!(QcMdpc::decrypt(&[], &private), None);

        let mut truncated = QcMdpc::encrypt(b"x", &public);
        truncated.pop();
        assert_eq!(QcMdpc::decrypt(&truncated, &private), None);

        // лишняя ошибка: t + 1 единиц, проверка веса должна отказать
        let mut tampered = QcMdpc::encrypt(b"x", &public);
        tampered[0] ^= 1;
        assert_eq!(QcMdpc::decrypt(&tampered, &private), None);
    }

    #[test]
    fn wrong_key_does_not_decrypt() {
        let (_, public) = QcMdpc::keygen(CRYPTO_PARAMS);
        let (other_private, _) = QcMdpc::keygen(CRYPTO_PARAMS);
        let encrypted = QcMdpc::encrypt(b"secret", &public);
        assert_eq!(QcMdpc::decrypt(&encrypted, &other_private), None);
    }
}
