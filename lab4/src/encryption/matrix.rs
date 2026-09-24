use rand::Rng;
use rand::seq::SliceRandom;
use std::ops::Range;

const WORD: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitVec {
    len: usize,
    words: Vec<u64>,
}

impl BitVec {
    pub fn zeros(len: usize) -> Self {
        return Self {
            len,
            words: vec![0; len.div_ceil(WORD)],
        };
    }

    pub fn random<R: Rng>(len: usize, rng: &mut R) -> Self {
        let mut v = Self::zeros(len);
        for word in &mut v.words {
            *word = rng.r#gen();
        }
        v.clear_tail();

        return v;
    }

    pub fn random_with_weight<R: Rng>(len: usize, weight: usize, rng: &mut R) -> Self {
        assert!(weight <= len, "weight {weight} exceeds length {len}");
        let mut v = Self::zeros(len);
        for i in rand::seq::index::sample(rng, len, weight) {
            v.set(i, true);
        }

        return v;
    }

    pub fn from_bit_string(bits: &str) -> Result<Self, String> {
        let bits: Vec<char> = bits.chars().filter(|c| !c.is_whitespace()).collect();
        let mut v = Self::zeros(bits.len());
        for (i, c) in bits.into_iter().enumerate() {
            match c {
                '0' => {}
                '1' => v.set(i, true),
                _ => return Err(format!("{c:?} is not a bit")),
            }
        }

        return Ok(v);
    }

    pub fn to_bit_string(&self) -> String {
        return (0..self.len)
            .map(|i| if self.get(i) { '1' } else { '0' })
            .collect();
    }

    fn clear_tail(&mut self) {
        let used = self.len % WORD;
        if used != 0 {
            *self.words.last_mut().unwrap() &= (1 << used) - 1;
        }
    }

    pub fn len(&self) -> usize {
        return self.len;
    }

    pub fn is_empty(&self) -> bool {
        return self.len == 0;
    }

    pub fn get(&self, i: usize) -> bool {
        assert!(i < self.len, "bit {i} out of range for length {}", self.len);

        return self.words[i / WORD] >> (i % WORD) & 1 == 1;
    }

    pub fn set(&mut self, i: usize, value: bool) {
        assert!(i < self.len, "bit {i} out of range for length {}", self.len);
        let mask = 1 << (i % WORD);
        if value {
            self.words[i / WORD] |= mask;
        } else {
            self.words[i / WORD] &= !mask;
        }
    }

    pub fn flip(&mut self, i: usize) {
        assert!(i < self.len, "bit {i} out of range for length {}", self.len);
        self.words[i / WORD] ^= 1 << (i % WORD);
    }

    pub fn xor_assign(&mut self, other: &BitVec) {
        assert_eq!(self.len, other.len, "length mismatch");
        for (a, b) in self.words.iter_mut().zip(&other.words) {
            *a ^= b;
        }
    }

    pub fn xor(&self, other: &BitVec) -> BitVec {
        let mut result = self.clone();
        result.xor_assign(other);

        return result;
    }

    pub fn weight(&self) -> usize {
        return self.words.iter().map(|w| w.count_ones() as usize).sum();
    }

    pub fn is_zero(&self) -> bool {
        return self.words.iter().all(|&w| w == 0);
    }

    pub fn iter_ones(&self) -> impl Iterator<Item = usize> + '_ {
        return self.words.iter().enumerate().flat_map(|(i, &word)| {
            let mut rest = word;
            return std::iter::from_fn(move || {
                if rest == 0 {
                    return None;
                }
                let bit = rest.trailing_zeros() as usize;
                rest &= rest - 1;
                return Some(i * WORD + bit);
            });
        });
    }

    pub fn prefix(&self, len: usize) -> BitVec {
        assert!(len <= self.len, "prefix longer than the vector");
        let mut v = Self {
            len,
            words: self.words[..len.div_ceil(WORD)].to_vec(),
        };
        v.clear_tail();

        return v;
    }

    pub fn slice(&self, range: Range<usize>) -> BitVec {
        assert!(range.end <= self.len, "slice out of bounds");
        let mut v = Self::zeros(range.len());
        for i in range.clone().filter(|&i| self.get(i)) {
            v.set(i - range.start, true);
        }

        return v;
    }

    pub fn last_one(&self) -> Option<usize> {
        let (i, word) = self
            .words
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)?;

        return Some(i * WORD + (WORD - 1 - word.leading_zeros() as usize));
    }

    pub fn from_bytes(bytes: &[u8], len: usize) -> Result<Self, String> {
        if bytes.len() != len.div_ceil(8) {
            return Err(format!(
                "{len} bits need {} bytes, got {}",
                len.div_ceil(8),
                bytes.len()
            ));
        }

        let mut v = Self::zeros(len);
        for (j, &byte) in bytes.iter().enumerate() {
            v.words[j / 8] |= (byte as u64) << (8 * (j % 8));
        }
        let weight = v.weight();
        v.clear_tail();
        if v.weight() != weight {
            return Err("bits set past the end of the vector".to_string());
        }

        return Ok(v);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        return (0..self.len.div_ceil(8))
            .map(|j| (self.words[j / 8] >> (8 * (j % 8))) as u8)
            .collect();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permutation {
    map: Vec<usize>,
}

impl Permutation {
    pub fn identity(n: usize) -> Self {
        return Self {
            map: (0..n).collect(),
        };
    }

    pub fn random<R: Rng>(n: usize, rng: &mut R) -> Self {
        let mut map: Vec<usize> = (0..n).collect();
        map.shuffle(rng);

        return Self { map };
    }

    pub fn from_vec(map: Vec<usize>) -> Result<Self, String> {
        let mut seen = vec![false; map.len()];
        for &target in &map {
            if target >= map.len() || seen[target] {
                return Err(format!("{map:?} is not a permutation"));
            }
            seen[target] = true;
        }

        return Ok(Self { map });
    }

    pub fn len(&self) -> usize {
        return self.map.len();
    }

    pub fn is_empty(&self) -> bool {
        return self.map.is_empty();
    }

    pub fn map(&self, i: usize) -> usize {
        return self.map[i];
    }

    pub fn as_slice(&self) -> &[usize] {
        return &self.map;
    }

    pub fn inverse(&self) -> Permutation {
        let mut map = vec![0; self.map.len()];
        for (i, &target) in self.map.iter().enumerate() {
            map[target] = i;
        }

        return Self { map };
    }

    pub fn apply(&self, v: &BitVec) -> BitVec {
        assert_eq!(v.len(), self.len(), "length mismatch");
        let mut result = BitVec::zeros(v.len());
        for i in v.iter_ones() {
            result.set(self.map[i], true);
        }

        return result;
    }

    pub fn permute<T: Clone>(&self, items: &[T]) -> Vec<T> {
        assert_eq!(items.len(), self.len(), "length mismatch");
        let mut result = items.to_vec();
        for (i, item) in items.iter().enumerate() {
            result[self.map[i]] = item.clone();
        }

        return result;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matrix {
    cols: usize,
    rows: Vec<BitVec>,
}

pub struct Systematic {
    pub matrix: Matrix,
    pub permutation: Permutation,
}

impl Matrix {
    pub fn zeros(rows: usize, cols: usize) -> Self {
        return Self {
            cols,
            rows: vec![BitVec::zeros(cols); rows],
        };
    }

    pub fn identity(n: usize) -> Self {
        let mut matrix = Self::zeros(n, n);
        for i in 0..n {
            matrix.rows[i].set(i, true);
        }

        return matrix;
    }

    pub fn random<R: Rng>(rows: usize, cols: usize, rng: &mut R) -> Self {
        return Self {
            cols,
            rows: (0..rows).map(|_| BitVec::random(cols, rng)).collect(),
        };
    }

    pub fn from_rows(cols: usize, rows: Vec<BitVec>) -> Self {
        assert!(rows.iter().all(|r| r.len() == cols), "row length mismatch");

        return Self { cols, rows };
    }

    pub fn row_count(&self) -> usize {
        return self.rows.len();
    }

    pub fn col_count(&self) -> usize {
        return self.cols;
    }

    pub fn row(&self, i: usize) -> &BitVec {
        return &self.rows[i];
    }

    pub fn rows(&self) -> &[BitVec] {
        return &self.rows;
    }

    pub fn get(&self, row: usize, col: usize) -> bool {
        return self.rows[row].get(col);
    }

    pub fn set(&mut self, row: usize, col: usize, value: bool) {
        self.rows[row].set(col, value);
    }

    pub fn vec_mul(&self, v: &BitVec) -> BitVec {
        assert_eq!(v.len(), self.row_count(), "length mismatch");
        let mut result = BitVec::zeros(self.cols);
        for i in v.iter_ones() {
            result.xor_assign(&self.rows[i]);
        }

        return result;
    }

    pub fn mul(&self, other: &Matrix) -> Matrix {
        return Self {
            cols: other.cols,
            rows: self.rows.iter().map(|row| other.vec_mul(row)).collect(),
        };
    }

    pub fn transpose(&self) -> Matrix {
        let mut result = Self::zeros(self.cols, self.row_count());
        for (i, row) in self.rows.iter().enumerate() {
            for j in row.iter_ones() {
                result.rows[j].set(i, true);
            }
        }

        return result;
    }

    pub fn permute_columns(&self, p: &Permutation) -> Matrix {
        return Self {
            cols: self.cols,
            rows: self.rows.iter().map(|row| p.apply(row)).collect(),
        };
    }

    pub fn columns(&self, range: Range<usize>) -> Matrix {
        assert!(range.end <= self.cols, "column range out of bounds");
        let mut result = Self::zeros(self.row_count(), range.len());
        for (i, row) in self.rows.iter().enumerate() {
            for j in row.iter_ones().filter(|j| range.contains(j)) {
                result.rows[i].set(j - range.start, true);
            }
        }

        return result;
    }

    pub fn hstack(&self, other: &Matrix) -> Matrix {
        assert_eq!(self.row_count(), other.row_count(), "row count mismatch");
        let mut result = Self::zeros(self.row_count(), self.cols + other.cols);
        for (i, (left, right)) in self.rows.iter().zip(&other.rows).enumerate() {
            for j in left.iter_ones() {
                result.rows[i].set(j, true);
            }
            for j in right.iter_ones() {
                result.rows[i].set(self.cols + j, true);
            }
        }

        return result;
    }

    pub fn inverse(&self) -> Option<Matrix> {
        let n = self.row_count();
        assert_eq!(n, self.cols, "only square matrices have inverses");

        let mut left = self.rows.clone();
        let mut right = Self::identity(n).rows;
        for col in 0..n {
            let found = (col..n).find(|&r| left[r].get(col))?;
            left.swap(col, found);
            right.swap(col, found);

            let (pivot_left, pivot_right) = (left[col].clone(), right[col].clone());
            for r in 0..n {
                if r != col && left[r].get(col) {
                    left[r].xor_assign(&pivot_left);
                    right[r].xor_assign(&pivot_right);
                }
            }
        }

        return Some(Self {
            cols: n,
            rows: right,
        });
    }

    pub fn random_invertible<R: Rng>(n: usize, rng: &mut R) -> (Matrix, Matrix) {
        loop {
            let candidate = Self::random(n, n, rng);
            if let Some(inverse) = candidate.inverse() {
                return (candidate, inverse);
            }
        }
    }

    pub fn systematic(&self) -> Systematic {
        let n = self.cols;
        let mut rows = self.rows.clone();
        let right = n.saturating_sub(rows.len());

        let mut pivots: Vec<usize> = vec![];
        for col in (right..n).chain((0..right).rev()) {
            let rank = pivots.len();
            if rank == rows.len() {
                break;
            }
            let Some(found) = (rank..rows.len()).find(|&r| rows[r].get(col)) else {
                continue;
            };
            rows.swap(rank, found);

            let pivot = rows[rank].clone();
            for (r, row) in rows.iter_mut().enumerate() {
                if r != rank && row.get(col) {
                    row.xor_assign(&pivot);
                }
            }
            pivots.push(col);
        }

        let rank = pivots.len();
        rows.truncate(rank);

        let k = n - rank;
        let mut map = vec![usize::MAX; n];
        for (j, &col) in pivots.iter().enumerate() {
            map[col] = k + j;
        }
        for (target, next) in map.iter_mut().filter(|t| **t == usize::MAX).zip(0..) {
            *target = next;
        }
        let permutation = Permutation { map };

        return Systematic {
            matrix: Self {
                cols: n,
                rows: rows.iter().map(|row| permutation.apply(row)).collect(),
            },
            permutation,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn rng() -> StdRng {
        return StdRng::seed_from_u64(4);
    }

    fn matrix(rows: &[&str]) -> Matrix {
        let rows: Vec<BitVec> = rows
            .iter()
            .map(|r| BitVec::from_bit_string(r).unwrap())
            .collect();

        return Matrix::from_rows(rows[0].len(), rows);
    }

    fn check_systematic(h: &Matrix) -> Systematic {
        let sys = h.systematic();
        let n = h.col_count();
        let rank = sys.matrix.row_count();
        let k = n - rank;

        assert_eq!(sys.matrix.columns(k..n), Matrix::identity(rank));

        let g = Matrix::identity(k).hstack(&sys.matrix.columns(0..k).transpose());
        assert_eq!(g.mul(&sys.matrix.transpose()), Matrix::zeros(k, rank));

        let g_original = g.permute_columns(&sys.permutation.inverse());
        assert_eq!(
            g_original.mul(&h.transpose()),
            Matrix::zeros(k, h.row_count())
        );

        return sys;
    }

    #[test]
    fn bit_vec_basics() {
        let mut v = BitVec::zeros(70);
        assert!(v.is_zero());
        v.set(0, true);
        v.set(64, true);
        v.flip(69);
        v.flip(64);
        assert!(v.get(0) && !v.get(64) && v.get(69));
        assert_eq!(v.weight(), 2);
        assert_eq!(v.iter_ones().collect::<Vec<_>>(), vec![0, 69]);

        let s = "1011010";
        assert_eq!(BitVec::from_bit_string(s).unwrap().to_bit_string(), s);
        assert_eq!(BitVec::from_bit_string("10 11").unwrap().len(), 4);
        assert!(BitVec::from_bit_string("102").is_err());
    }

    #[test]
    fn bit_vec_tail_stays_clear() {
        let mut rng = rng();
        for len in [1, 63, 64, 65, 130] {
            let v = BitVec::random(len, &mut rng);
            assert!(v.weight() <= len);
            for k in [0, len / 2, len] {
                let prefix = v.prefix(k);
                assert_eq!(prefix.len(), k);
                assert!(prefix.iter_ones().all(|i| v.get(i)));
                assert_eq!(prefix.weight(), v.iter_ones().filter(|&i| i < k).count());
            }
        }
    }

    #[test]
    fn bytes_round_trip() {
        let v = BitVec::from_bytes(&[0b0000_0101, 0b1000_0000], 16).unwrap();
        assert_eq!(v.iter_ones().collect::<Vec<_>>(), vec![0, 2, 15]);
        assert_eq!(v.to_bytes(), vec![0b0000_0101, 0b1000_0000]);

        let mut rng = rng();
        for len in [0, 1, 7, 8, 9, 63, 64, 65, 200] {
            let v = BitVec::random(len, &mut rng);
            let bytes = v.to_bytes();
            assert_eq!(bytes.len(), len.div_ceil(8));
            assert_eq!(BitVec::from_bytes(&bytes, len).unwrap(), v);
        }

        assert!(BitVec::from_bytes(&[0xFF], 7).is_err());
        assert!(BitVec::from_bytes(&[0x7F], 7).is_ok());
        assert!(BitVec::from_bytes(&[0, 0], 8).is_err());
    }

    #[test]
    fn slice_and_last_one() {
        let v = BitVec::from_bit_string("0011010010").unwrap();
        assert_eq!(v.slice(2..7).to_bit_string(), "11010");
        assert_eq!(v.slice(3..3).len(), 0);
        assert_eq!(v.last_one(), Some(8));
        assert_eq!(BitVec::zeros(100).last_one(), None);

        let mut rng = rng();
        let v = BitVec::random(300, &mut rng);
        assert_eq!(v.last_one(), v.iter_ones().last());
        assert_eq!(v.slice(0..150), v.prefix(150));
        for i in 0..200 {
            assert_eq!(v.slice(50..250).get(i), v.get(50 + i));
        }
    }

    #[test]
    fn random_with_weight_is_exact() {
        let mut rng = rng();
        for (len, weight) in [(16, 0), (16, 2), (16, 16), (1024, 50)] {
            for _ in 0..20 {
                assert_eq!(
                    BitVec::random_with_weight(len, weight, &mut rng).weight(),
                    weight
                );
            }
        }
    }

    #[test]
    fn permutation_round_trip() {
        let mut rng = rng();
        let p = Permutation::random(100, &mut rng);
        let mut sorted = p.as_slice().to_vec();
        sorted.sort();
        assert_eq!(sorted, (0..100).collect::<Vec<_>>());

        let v = BitVec::random(100, &mut rng);
        assert_eq!(p.inverse().apply(&p.apply(&v)), v);
        assert_eq!(p.apply(&v).weight(), v.weight());

        let bits: Vec<bool> = (0..100).map(|i| v.get(i)).collect();
        let moved = p.apply(&v);
        assert_eq!(
            p.permute(&bits),
            (0..100).map(|i| moved.get(i)).collect::<Vec<_>>()
        );

        assert!(Permutation::from_vec(vec![2, 0, 1]).is_ok());
        assert!(Permutation::from_vec(vec![0, 0, 2]).is_err());
        assert!(Permutation::from_vec(vec![0, 3]).is_err());
    }

    #[test]
    fn products() {
        let mut rng = rng();
        let a = Matrix::random(7, 70, &mut rng);
        let b = Matrix::random(70, 9, &mut rng);
        let v = BitVec::random(7, &mut rng);

        assert_eq!(b.vec_mul(&a.vec_mul(&v)), a.mul(&b).vec_mul(&v));
        assert_eq!(a.mul(&b).transpose(), b.transpose().mul(&a.transpose()));
        assert_eq!(a.transpose().transpose(), a);
        assert_eq!(Matrix::identity(7).mul(&a), a);
        assert_eq!(a.mul(&Matrix::identity(70)), a);
    }

    #[test]
    fn column_permutation_matches_vector_permutation() {
        let mut rng = rng();
        let m = Matrix::random(8, 20, &mut rng);
        let p = Permutation::random(20, &mut rng);
        let v = BitVec::random(8, &mut rng);
        assert_eq!(m.permute_columns(&p).vec_mul(&v), p.apply(&m.vec_mul(&v)));
    }

    #[test]
    fn columns_and_hstack() {
        let m = matrix(&["10110", "01011"]);
        assert_eq!(m.columns(0..2), matrix(&["10", "01"]));
        assert_eq!(m.columns(2..5), matrix(&["110", "011"]));
        assert_eq!(m.columns(0..2).hstack(&m.columns(2..5)), m);
    }

    #[test]
    fn inverse() {
        let mut rng = rng();
        for n in [1, 5, 64, 100] {
            let (m, inv) = Matrix::random_invertible(n, &mut rng);
            assert_eq!(m.mul(&inv), Matrix::identity(n));
            assert_eq!(inv.mul(&m), Matrix::identity(n));
        }

        assert_eq!(matrix(&["110", "011", "101"]).inverse(), None);
        assert_eq!(Matrix::zeros(3, 3).inverse(), None);
    }

    #[test]
    fn systematic_keeps_ready_matrices() {
        let h = matrix(&["1101100", "1011010", "0111001"]);
        let sys = check_systematic(&h);
        assert_eq!(sys.permutation, Permutation::identity(7));
        assert_eq!(sys.matrix, h);
    }

    #[test]
    fn systematic_random() {
        let mut rng = rng();
        for (rows, cols) in [(8, 16), (32, 64), (40, 100)] {
            for _ in 0..20 {
                check_systematic(&Matrix::random(rows, cols, &mut rng));
            }
        }
    }

    #[test]
    fn systematic_with_singular_right_block() {
        let h = matrix(&["1101100", "1011010", "0111000"]);
        let sys = check_systematic(&h);
        assert_eq!(sys.matrix.row_count(), 3);
        assert_ne!(sys.permutation, Permutation::identity(7));
    }

    #[test]
    fn systematic_drops_dependent_rows() {
        let mut rng = rng();
        let mut rows = Matrix::random(6, 20, &mut rng).rows().to_vec();
        rows.push(rows[0].xor(&rows[1]));
        rows.push(BitVec::zeros(20));
        let h = Matrix::from_rows(20, rows);

        let sys = check_systematic(&h);
        assert!(sys.matrix.row_count() <= 6);
        assert_eq!(
            sys.matrix.row_count(),
            h.transpose().systematic().matrix.row_count()
        );
    }
}
