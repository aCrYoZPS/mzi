use rand::Rng;
use rand::seq::index::sample;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenseBitVec {
    r: usize,
    words: Vec<u64>,
}

impl DenseBitVec {
    pub fn zero(r: usize) -> Self {
        let len = r.div_ceil(64);
        return Self {
            r,
            words: vec![0u64; len],
        };
    }

    pub fn one(r: usize) -> Self {
        let len = r.div_ceil(64);
        let mut words = vec![0u64; len];
        words[0] = 1;
        return Self { r, words };
    }

    fn mask(r: usize) -> u64 {
        return if r % 64 == 0 {
            u64::MAX
        } else {
            (1u64 << (r % 64)) - 1
        };
    }

    pub fn random_odd<R: Rng>(r: usize, rng: &mut R) -> Self {
        let len = r.div_ceil(64);
        let mask = Self::mask(r);
        loop {
            let mut words: Vec<u64> = (0..len).map(|_| rng.next_u64()).collect();
            words[len - 1] &= mask;

            if words.iter().map(|w| w.count_ones()).sum::<u32>() % 2 == 0 {
                words[0] ^= 1;
            }

            if words.iter().map(|w| w.count_ones()).sum::<u32>() != r as u32 {
                return Self { r, words };
            }
        }
    }

    pub fn from_bytes(r: usize, bytes: &[u8]) -> Self {
        let len = r.div_ceil(64);
        let mask = Self::mask(r);

        assert!(r.div_ceil(8) >= bytes.len());

        let mut words: Vec<u64> = Vec::with_capacity(len);

        for block in bytes.chunks(8) {
            let mut block_bytes = [0u8; 8];
            block_bytes[..block.len()].copy_from_slice(block);
            words.push(u64::from_le_bytes(block_bytes));
        }

        words.resize(len, 0);
        words[len - 1] &= mask;

        return Self { r, words };
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(self.words.len() * 8);
        for word in &self.words {
            res.extend_from_slice(&word.to_le_bytes());
        }
        res.truncate(self.r.div_ceil(8));
        return res;
    }

    pub fn to_bit_string(&self) -> String {
        return (0..self.r)
            .map(|i| if self.get(i) { '1' } else { '0' })
            .collect();
    }

    pub fn r(&self) -> usize {
        return self.r;
    }

    pub fn get(&self, i: usize) -> bool {
        assert!(i < self.r, "bit {i} is out of range for r = {}", self.r);
        return (self.words[i / 64] >> (i % 64)) & 1 == 1;
    }

    pub fn set(&mut self, i: usize, value: bool) {
        assert!(i < self.r, "bit {i} is out of range for r = {}", self.r);
        if value {
            self.words[i / 64] |= 1u64 << (i % 64);
        } else {
            self.words[i / 64] &= !(1u64 << (i % 64));
        }
    }

    pub fn flip(&mut self, i: usize) {
        assert!(i < self.r, "bit {i} is out of range for r = {}", self.r);
        self.words[i / 64] ^= 1u64 << (i % 64);
    }

    pub fn weight(&self) -> usize {
        return self.words.iter().map(|w| w.count_ones() as usize).sum();
    }

    pub fn is_zero(&self) -> bool {
        return self.words.iter().all(|&w| w == 0);
    }

    pub fn support(&self) -> Vec<usize> {
        let mut res = Vec::new();
        for (k, &word) in self.words.iter().enumerate() {
            let mut w = word;
            while w != 0 {
                res.push(k * 64 + w.trailing_zeros() as usize);
                w &= w - 1;
            }
        }
        return res;
    }

    pub fn xor(&self, other: &DenseBitVec) -> DenseBitVec {
        let mut res = self.clone();
        res.xor_assign(other);
        return res;
    }

    pub fn xor_assign(&mut self, other: &DenseBitVec) {
        assert_eq!(self.r, other.r, "vectors from different rings");
        for (a, b) in self.words.iter_mut().zip(&other.words) {
            *a ^= b;
        }
    }

    pub fn xor_sparse_assign(&mut self, other: &SparseBitVec) {
        assert_eq!(self.r, other.r, "vectors from different rings");
        for &i in &other.set_bits {
            self.flip(i);
        }
    }

    fn xor_shifted(&mut self, src: &DenseBitVec, j: usize) {
        let r = self.r;
        let n = self.words.len();
        let j = j % r;

        let (q, s) = (j / 64, j % 64);
        for k in q..n {
            let mut w = src.words[k - q] << s;
            if s > 0 && k > q {
                w |= src.words[k - q - 1] >> (64 - s);
            }
            self.words[k] ^= w;
        }

        if j > 0 {
            let (q, s) = ((r - j) / 64, (r - j) % 64);
            for k in 0..n - q {
                let mut w = src.words[k + q] >> s;
                if s > 0 && k + q + 1 < n {
                    w |= src.words[k + q + 1] << (64 - s);
                }
                self.words[k] ^= w;
            }
        }

        self.words[n - 1] &= Self::mask(r);
    }

    pub fn shift(&self, j: usize) -> DenseBitVec {
        let mut res = DenseBitVec::zero(self.r);
        res.xor_shifted(self, j);
        return res;
    }

    pub fn mul(&self, other: &DenseBitVec) -> DenseBitVec {
        assert_eq!(self.r, other.r, "vectors from different rings");
        let mut res = DenseBitVec::zero(self.r);
        for i in self.support() {
            res.xor_shifted(other, i);
        }
        return res;
    }

    pub fn square(&self) -> DenseBitVec {
        let mut res = DenseBitVec::zero(self.r);
        for i in self.support() {
            res.flip(2 * i % self.r);
        }
        return res;
    }

    pub fn inverse(&self) -> Option<DenseBitVec> {
        let r = self.r;
        let len = (r + 1).div_ceil(64);

        let mut r0 = vec![0u64; len];
        r0[0] = 1;
        r0[r / 64] |= 1u64 << (r % 64);
        let mut r1 = self.words.clone();
        r1.resize(len, 0);

        let mut v0 = DenseBitVec::zero(r);
        let mut v1 = DenseBitVec::one(r);

        loop {
            let d1 = degree(&r1)?;
            if d1 == 0 {
                return Some(v1);
            }

            while let Some(d0) = degree(&r0) {
                if d0 < d1 {
                    break;
                }
                xor_shifted_plain(&mut r0, &r1, d0 - d1);
                v0.xor_shifted(&v1, d0 - d1);
            }

            std::mem::swap(&mut r0, &mut r1);
            std::mem::swap(&mut v0, &mut v1);
        }
    }
}

fn degree(words: &[u64]) -> Option<usize> {
    let k = words.iter().rposition(|&w| w != 0)?;
    return Some(k * 64 + 63 - words[k].leading_zeros() as usize);
}

fn xor_shifted_plain(dst: &mut [u64], src: &[u64], s: usize) {
    let (q, s) = (s / 64, s % 64);
    for k in q..dst.len() {
        let mut w = src[k - q] << s;
        if s > 0 && k > q {
            w |= src[k - q - 1] >> (64 - s);
        }
        dst[k] ^= w;
    }
}

impl From<&SparseBitVec> for DenseBitVec {
    fn from(value: &SparseBitVec) -> Self {
        let len = value.r.div_ceil(64);
        let mut words: Vec<u64> = vec![0u64; len];
        for &bit in &value.set_bits {
            let word = bit / 64;
            let bit_idx = bit % 64;

            words[word] |= 1u64 << bit_idx;
        }

        return Self { r: value.r, words };
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseBitVec {
    r: usize,
    set_bits: Vec<usize>,
}

impl SparseBitVec {
    pub fn random<R: Rng>(r: usize, d: usize, rng: &mut R) -> Self {
        let mut set_bits = sample(rng, r, d).into_vec();
        set_bits.sort_unstable();

        return Self { r, set_bits };
    }

    pub fn from_positions(r: usize, mut positions: Vec<usize>) -> Self {
        positions.sort_unstable();
        assert!(
            positions.windows(2).all(|p| p[0] < p[1]),
            "positions must be distinct"
        );
        assert!(
            positions.last().is_none_or(|&p| p < r),
            "positions must be less than r = {r}"
        );
        return Self {
            r,
            set_bits: positions,
        };
    }

    pub fn r(&self) -> usize {
        return self.r;
    }

    pub fn weight(&self) -> usize {
        return self.set_bits.len();
    }

    pub fn positions(&self) -> &[usize] {
        return &self.set_bits;
    }

    pub fn mul(&self, other: &DenseBitVec) -> DenseBitVec {
        assert_eq!(self.r, other.r, "vectors from different rings");
        let mut res = DenseBitVec::zero(self.r);
        for &i in &self.set_bits {
            res.xor_shifted(other, i);
        }
        return res;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    const RINGS: [usize; 3] = [11, 587, 1019];
    const WORD_EDGES: [usize; 7] = [5, 11, 63, 64, 65, 128, 587];

    fn rng() -> StdRng {
        return StdRng::seed_from_u64(4);
    }

    fn dense(r: usize, positions: &[usize]) -> DenseBitVec {
        return DenseBitVec::from(&SparseBitVec::from_positions(r, positions.to_vec()));
    }

    fn monomial(r: usize, j: usize) -> DenseBitVec {
        return dense(r, &[j]);
    }

    fn all_ones(r: usize) -> DenseBitVec {
        return dense(r, &(0..r).collect::<Vec<_>>());
    }

    fn random_dense<R: Rng>(r: usize, rng: &mut R) -> DenseBitVec {
        let bytes: Vec<u8> = (0..r.div_ceil(8))
            .map(|_| rng.gen_range(0..=u8::MAX))
            .collect();
        return DenseBitVec::from_bytes(r, &bytes);
    }

    fn naive_shift(a: &DenseBitVec, j: usize) -> DenseBitVec {
        let r = a.r();
        let mut out = DenseBitVec::zero(r);
        for i in 0..r {
            if a.get(i) {
                out.flip((i + j) % r);
            }
        }
        return out;
    }

    fn naive_mul(a: &DenseBitVec, b: &DenseBitVec) -> DenseBitVec {
        let r = a.r();
        let mut out = DenseBitVec::zero(r);
        for i in 0..r {
            if !a.get(i) {
                continue;
            }
            for j in 0..r {
                if b.get(j) {
                    out.flip((i + j) % r);
                }
            }
        }
        return out;
    }

    fn fermat_inverse(a: &DenseBitVec) -> DenseBitVec {
        let r = a.r();
        let mut out = DenseBitVec::one(r);
        for _ in 0..r - 2 {
            out = out.square().mul(a);
        }
        return out.square();
    }

    #[test]
    fn zero_and_one() {
        for r in WORD_EDGES {
            let zero = DenseBitVec::zero(r);
            assert_eq!(zero.r(), r);
            assert!(zero.is_zero());
            assert_eq!(zero.weight(), 0);

            let one = DenseBitVec::one(r);
            assert_eq!(one.r(), r);
            assert!(!one.is_zero());
            assert_eq!(one.support(), vec![0]);
        }
    }

    #[test]
    fn bit_string_lists_coefficients_from_a0() {
        assert_eq!(dense(5, &[0, 2]).to_bit_string(), "10100");
        assert_eq!(dense(11, &[1, 4, 5, 6, 8]).to_bit_string(), "01001110100");
        assert_eq!(DenseBitVec::zero(3).to_bit_string(), "000");
    }

    #[test]
    fn get_set_flip_across_word_boundaries() {
        let r = 587;
        let mut v = DenseBitVec::zero(r);
        let positions = [0, 1, 63, 64, 127, 128, 575, 576, 586];
        for (count, &i) in positions.iter().enumerate() {
            assert!(!v.get(i));
            v.set(i, true);
            assert!(v.get(i));
            assert_eq!(v.weight(), count + 1);
        }
        assert_eq!(v.support(), positions.to_vec());

        for &i in &positions {
            v.flip(i);
            assert!(!v.get(i));
        }
        assert!(v.is_zero());

        v.set(64, true);
        v.set(64, true);
        assert_eq!(v.weight(), 1);
        v.set(64, false);
        assert!(v.is_zero());
    }

    #[test]
    #[should_panic]
    fn get_beyond_r_panics() {
        DenseBitVec::zero(587).get(587);
    }

    #[test]
    #[should_panic]
    fn flip_beyond_r_panics() {
        DenseBitVec::zero(11).flip(11);
    }

    #[test]
    fn from_bytes_uses_lsb_first_order() {
        let v = DenseBitVec::from_bytes(11, &[0b0000_0101, 0b0000_0100]);
        assert_eq!(v.support(), vec![0, 2, 10]);
        assert_eq!(v.to_bytes(), vec![0b0000_0101, 0b0000_0100]);
    }

    #[test]
    fn from_bytes_clears_bits_beyond_r() {
        for r in [11, 63, 64, 65, 587, 12323] {
            let v = DenseBitVec::from_bytes(r, &vec![0xFF; r.div_ceil(8)]);
            assert_eq!(v.weight(), r, "r = {r}");
            assert_eq!(v, all_ones(r), "r = {r}");

            let bytes = v.to_bytes();
            assert_eq!(bytes.len(), r.div_ceil(8));
            if r % 8 != 0 {
                assert_eq!(*bytes.last().unwrap(), (1u8 << (r % 8)) - 1, "r = {r}");
            }
        }
    }

    #[test]
    fn from_bytes_pads_short_input() {
        for r in [11, 587, 12323] {
            let v = DenseBitVec::from_bytes(r, &vec![0xFF; r / 8]);
            assert_eq!(v.r(), r);
            assert_eq!(v.weight(), r / 8 * 8);
            assert_eq!(v.to_bytes().len(), r.div_ceil(8));
            assert_eq!(v.xor(&DenseBitVec::zero(r)), v);
        }
        assert!(DenseBitVec::from_bytes(587, &[]).is_zero());
    }

    #[test]
    #[should_panic]
    fn from_bytes_rejects_too_many_bytes() {
        DenseBitVec::from_bytes(587, &[0; 75]);
    }

    #[test]
    fn bytes_roundtrip() {
        let mut rng = rng();
        for r in WORD_EDGES {
            for _ in 0..50 {
                let v = random_dense(r, &mut rng);
                assert_eq!(DenseBitVec::from_bytes(r, &v.to_bytes()), v);
            }
        }
    }

    #[test]
    fn random_odd_has_invertible_shape() {
        let mut rng = rng();
        for r in [11, 63, 64, 65, 587] {
            for _ in 0..1000 {
                let a = DenseBitVec::random_odd(r, &mut rng);
                assert_eq!(a.r(), r);
                assert_eq!(a.weight() % 2, 1, "r = {r}");
                assert_ne!(a.weight(), r, "r = {r}: all ones is not invertible");
                assert!(a.support().iter().all(|&i| i < r), "r = {r}: tail is dirty");
            }
        }
    }

    #[test]
    fn sparse_random_has_exact_weight() {
        let mut rng = rng();
        for (r, d) in [(11, 3), (587, 15), (1019, 21), (12323, 71)] {
            for _ in 0..100 {
                let h = SparseBitVec::random(r, d, &mut rng);
                assert_eq!(h.r(), r);
                assert_eq!(h.weight(), d);
                assert!(h.positions().windows(2).all(|p| p[0] < p[1]));
                assert!(h.positions().iter().all(|&i| i < r));
            }
        }
    }

    #[test]
    fn sparse_from_positions_sorts() {
        let h = SparseBitVec::from_positions(11, vec![8, 0, 3]);
        assert_eq!(h.positions(), &[0, 3, 8]);
        assert_eq!(h.weight(), 3);
    }

    #[test]
    #[should_panic]
    fn sparse_from_positions_rejects_duplicates() {
        SparseBitVec::from_positions(11, vec![1, 5, 1]);
    }

    #[test]
    #[should_panic]
    fn sparse_from_positions_rejects_out_of_range() {
        SparseBitVec::from_positions(11, vec![0, 11]);
    }

    #[test]
    fn dense_from_sparse_keeps_positions() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let h = SparseBitVec::random(r, r.min(15), &mut rng);
            let d = DenseBitVec::from(&h);
            assert_eq!(d.r(), r);
            assert_eq!(d.support(), h.positions().to_vec());
        }
    }

    #[test]
    fn support_matches_get() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let v = random_dense(r, &mut rng);
            let expected: Vec<usize> = (0..r).filter(|&i| v.get(i)).collect();
            assert_eq!(v.support(), expected);
            assert_eq!(v.weight(), expected.len());
        }
    }

    #[test]
    fn xor_is_bitwise_addition() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let a = random_dense(r, &mut rng);
            let b = random_dense(r, &mut rng);
            let c = a.xor(&b);
            for i in 0..r {
                assert_eq!(c.get(i), a.get(i) != b.get(i));
            }
            assert_eq!(c, b.xor(&a));
            assert_eq!(a.xor(&a), DenseBitVec::zero(r));
            assert_eq!(a.xor(&DenseBitVec::zero(r)), a);

            let mut d = a.clone();
            d.xor_assign(&b);
            assert_eq!(d, c);
        }
    }

    #[test]
    fn xor_sparse_matches_dense_xor() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let a = random_dense(r, &mut rng);
            let e = SparseBitVec::random(r, r.min(10), &mut rng);
            let mut b = a.clone();
            b.xor_sparse_assign(&e);
            assert_eq!(b, a.xor(&DenseBitVec::from(&e)));
        }
    }

    #[test]
    #[should_panic]
    fn xor_rejects_different_r() {
        DenseBitVec::zero(587).xor(&DenseBitVec::zero(1019));
    }

    #[test]
    fn shift_small_examples() {
        assert_eq!(dense(5, &[1, 4]).shift(2), dense(5, &[1, 3]));
        assert_eq!(monomial(11, 10).shift(1), DenseBitVec::one(11));
        assert_eq!(monomial(587, 586).shift(1), DenseBitVec::one(587));
        assert_eq!(monomial(64, 63).shift(1), DenseBitVec::one(64));
    }

    #[test]
    fn shift_of_monomials() {
        for r in WORD_EDGES {
            let ks = [
                0,
                1,
                2,
                31,
                63,
                64,
                65,
                127,
                128,
                r - 1,
                r,
                r + 1,
                2 * r + 3,
            ];
            for j in 0..r {
                for &k in &ks {
                    assert_eq!(
                        monomial(r, j).shift(k),
                        monomial(r, (j + k) % r),
                        "r = {r}, x^{j} * x^{k}"
                    );
                }
            }
        }
    }

    #[test]
    fn shift_matches_naive() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let a = random_dense(r, &mut rng);
            for j in 0..r {
                let shifted = a.shift(j);
                assert_eq!(shifted, naive_shift(&a, j), "r = {r}, j = {j}");
                assert_eq!(shifted.weight(), a.weight());
            }
        }
    }

    #[test]
    fn shift_by_r_is_identity_and_shifts_compose() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let a = random_dense(r, &mut rng);
            assert_eq!(a.shift(0), a);
            assert_eq!(a.shift(r), a);
            for _ in 0..50 {
                let j = rng.gen_range(0..r);
                let k = rng.gen_range(0..r);
                assert_eq!(a.shift(j).shift(k), a.shift((j + k) % r));
            }
        }
    }

    #[test]
    fn convolution_small_example() {
        let a = SparseBitVec::from_positions(5, vec![0, 2]);
        let b = dense(5, &[1, 4]);
        let expected = dense(5, &[3, 4]);
        assert_eq!(a.mul(&b), expected);
        assert_eq!(DenseBitVec::from(&a).mul(&b), expected);
        assert_eq!(b.mul(&DenseBitVec::from(&a)), expected);
    }

    #[test]
    fn multiplying_by_monomial_is_shift() {
        let mut rng = rng();
        for r in WORD_EDGES {
            let a = random_dense(r, &mut rng);
            for j in [0, 1, 63, 64, r - 1].into_iter().filter(|&j| j < r) {
                assert_eq!(a.mul(&monomial(r, j)), a.shift(j));
                assert_eq!(SparseBitVec::from_positions(r, vec![j]).mul(&a), a.shift(j));
            }
        }
    }

    #[test]
    fn sparse_mul_matches_naive() {
        let mut rng = rng();
        for (r, d) in [(11, 3), (587, 15), (1019, 21)] {
            for _ in 0..10 {
                let h = SparseBitVec::random(r, d, &mut rng);
                let b = random_dense(r, &mut rng);
                assert_eq!(h.mul(&b), naive_mul(&DenseBitVec::from(&h), &b), "r = {r}");
            }
        }
    }

    #[test]
    fn dense_mul_matches_naive() {
        let mut rng = rng();
        for r in WORD_EDGES {
            for _ in 0..3 {
                let a = random_dense(r, &mut rng);
                let b = random_dense(r, &mut rng);
                assert_eq!(a.mul(&b), naive_mul(&a, &b), "r = {r}");
            }
        }
    }

    #[test]
    fn sparse_mul_matches_dense_mul() {
        let mut rng = rng();
        for (r, d) in [(587, 15), (12323, 71)] {
            let h = SparseBitVec::random(r, d, &mut rng);
            let b = random_dense(r, &mut rng);
            assert_eq!(h.mul(&b), DenseBitVec::from(&h).mul(&b), "r = {r}");
        }
    }

    #[test]
    fn ring_laws() {
        let mut rng = rng();
        for r in RINGS {
            let a = random_dense(r, &mut rng);
            let b = random_dense(r, &mut rng);
            let c = random_dense(r, &mut rng);
            let zero = DenseBitVec::zero(r);
            let one = DenseBitVec::one(r);

            assert_eq!(a.mul(&b), b.mul(&a), "commutative, r = {r}");
            assert_eq!(a.mul(&one), a, "identity, r = {r}");
            assert_eq!(a.mul(&zero), zero, "zero, r = {r}");
            assert_eq!(
                a.mul(&b.xor(&c)),
                a.mul(&b).xor(&a.mul(&c)),
                "distributive, r = {r}"
            );
            assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)), "associative, r = {r}");
        }
    }

    #[test]
    fn ring_has_zero_divisors() {
        for r in RINGS {
            assert!(dense(r, &[0, 1]).mul(&all_ones(r)).is_zero(), "r = {r}");
        }
    }

    #[test]
    #[should_panic]
    fn mul_rejects_different_r() {
        DenseBitVec::one(587).mul(&DenseBitVec::one(1019));
    }

    #[test]
    fn square_doubles_exponents() {
        let mut rng = rng();
        for (r, d) in [(11, 3), (587, 15), (1019, 21)] {
            let h = SparseBitVec::random(r, d, &mut rng);
            let mut expected: Vec<usize> = h.positions().iter().map(|&i| 2 * i % r).collect();
            expected.sort_unstable();
            let squared = DenseBitVec::from(&h).square();
            assert_eq!(squared.support(), expected, "r = {r}");
        }
    }

    #[test]
    fn square_matches_mul() {
        let mut rng = rng();
        for r in [5, 11, 63, 65, 587] {
            let a = random_dense(r, &mut rng);
            assert_eq!(a.square(), a.mul(&a), "r = {r}");
        }
    }

    #[test]
    fn inverse_of_random_odd() {
        let mut rng = rng();
        for r in RINGS {
            for _ in 0..20 {
                let a = DenseBitVec::random_odd(r, &mut rng);
                let inv = a.inverse().expect("odd weight, not all ones");
                assert_eq!(a.mul(&inv), DenseBitVec::one(r), "r = {r}");
            }
        }
    }

    #[test]
    fn inverse_of_sparse_key() {
        let mut rng = rng();
        for (r, d) in [(11, 3), (587, 15), (1019, 21)] {
            for _ in 0..20 {
                let h = DenseBitVec::from(&SparseBitVec::random(r, d, &mut rng));
                let inv = h.inverse().expect("odd d");
                assert_eq!(h.mul(&inv), DenseBitVec::one(r), "r = {r}");
            }
        }
    }

    #[test]
    fn inverse_of_one_is_one() {
        for r in RINGS {
            assert_eq!(DenseBitVec::one(r).inverse(), Some(DenseBitVec::one(r)));
        }
    }

    #[test]
    fn non_invertible_elements() {
        let mut rng = rng();
        for r in RINGS {
            assert_eq!(DenseBitVec::zero(r).inverse(), None, "zero, r = {r}");
            assert_eq!(all_ones(r).inverse(), None, "all ones, r = {r}");
            assert_eq!(dense(r, &[0, 1]).inverse(), None, "1 + x, r = {r}");
            for _ in 0..20 {
                let mut even = DenseBitVec::random_odd(r, &mut rng);
                even.flip(0);
                assert_eq!(even.inverse(), None, "even weight, r = {r}");
            }
        }
    }

    #[test]
    fn inverse_matches_fermat() {
        let mut rng = rng();
        for r in [11, 13, 59, 587] {
            for _ in 0..5 {
                let a = DenseBitVec::random_odd(r, &mut rng);
                assert_eq!(a.inverse(), Some(fermat_inverse(&a)), "r = {r}");
            }
        }
    }

    #[test]
    fn level1_ring() {
        let mut rng = rng();
        let r = 12323;
        let h0 = SparseBitVec::random(r, 71, &mut rng);
        let h1 = DenseBitVec::from(&SparseBitVec::random(r, 71, &mut rng));
        let q = h0.mul(&h1.inverse().unwrap());
        assert_eq!(h1.mul(&q), DenseBitVec::from(&h0));

        let a = DenseBitVec::random_odd(r, &mut rng);
        assert_eq!(a.mul(&a.inverse().unwrap()), DenseBitVec::one(r));
    }

    #[test]
    fn spec_mini_example() {
        let r = 11;
        let h0 = SparseBitVec::from_positions(r, vec![0, 1, 2]);
        let h1 = SparseBitVec::from_positions(r, vec![0, 1, 3]);
        let h1_dense = DenseBitVec::from(&h1);

        let h1_inv = h1_dense.inverse().unwrap();
        assert_eq!(h1_inv, dense(r, &[0, 1, 3, 6, 7, 8, 10]));
        assert_eq!(h1.mul(&h1_inv), DenseBitVec::one(r));

        let q = h0.mul(&h1_inv);
        assert_eq!(q, dense(r, &[1, 4, 5, 6, 8]));
        assert_eq!(h1.mul(&q), DenseBitVec::from(&h0));

        assert_eq!(h1_dense.square(), dense(r, &[0, 2, 6]));

        let m = dense(r, &[0, 2, 3, 8]);
        let mq = m.mul(&q);
        assert_eq!(mq, dense(r, &[0, 2, 8, 10]));

        let c0 = m.clone();
        let mut c1 = mq;
        c1.xor_sparse_assign(&SparseBitVec::from_positions(r, vec![5]));
        assert_eq!(c1, dense(r, &[0, 2, 5, 8, 10]));

        let s = h0.mul(&c0).xor(&h1.mul(&c1));
        assert_eq!(s, dense(r, &[5, 6, 8]));
        assert_eq!(s, h1_dense.shift(5));
    }
}
