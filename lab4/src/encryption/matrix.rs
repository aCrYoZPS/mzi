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
