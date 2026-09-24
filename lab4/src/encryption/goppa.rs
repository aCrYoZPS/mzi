use super::gf::{Field, Gf, MAX_M, MIN_M};
use super::matrix::{BitVec, Matrix};
use super::poly::Poly;
use rand::Rng;
use rand::seq::SliceRandom;

/// A binary Goppa code Γ(L, g): the vectors c ∈ GF(2)^n with Σ cᵢ/(x - αᵢ) ≡ 0 (mod g),
/// where L = (α₁, …, αₙ) are distinct elements of GF(2^m) and g is irreducible of degree t.
/// It corrects t errors with Patterson's algorithm.
pub struct Goppa {
    field: Field,
    /// Ordered so that the generator matrix is systematic, [I_k | Aᵀ].
    support: Vec<Gf>,
    g: Poly,
    /// √x mod g, for the square root in Patterson's algorithm.
    sqrt_x: Poly,
    /// syndrome_terms[i] = (x - αᵢ)⁻¹ mod g, the contribution of an error in position i.
    syndrome_terms: Vec<Poly>,
    generator: Matrix,
}

impl Goppa {
    /// A random code: n distinct support elements and a random irreducible g of degree t.
    pub fn generate<R: Rng>(m: u32, n: usize, t: usize, rng: &mut R) -> Result<Self, String> {
        if !(MIN_M..=MAX_M).contains(&m) {
            return Err(format!("m must be in {MIN_M}..={MAX_M}"));
        }
        let field = Field::new(m);
        if n > field.size() {
            return Err(format!("n = {n} exceeds the field size 2^{m}"));
        }
        if t < 2 {
            return Err("t must be at least 2".to_string());
        }
        if m as usize * t >= n {
            return Err(format!(
                "m·t = {} leaves no room for data in n = {n}",
                m as usize * t
            ));
        }

        let mut elements: Vec<Gf> = (0..field.size() as Gf).collect();
        elements.shuffle(rng);
        elements.truncate(n);
        let g = Poly::random_irreducible(t, rng, &field);

        return Self::from_parts(field, elements, g);
    }

    /// Builds the code from a given support and Goppa polynomial. The support may come back
    /// reordered: see `support`.
    pub fn from_parts(field: Field, support: Vec<Gf>, g: Poly) -> Result<Self, String> {
        let n = support.len();
        let mut seen = vec![false; field.size()];
        for &alpha in &support {
            if alpha as usize >= field.size() {
                return Err(format!("{alpha} is not an element of GF(2^{})", field.m()));
            }
            if seen[alpha as usize] {
                return Err(format!(
                    "{} appears twice in the support",
                    field.display(alpha)
                ));
            }
            seen[alpha as usize] = true;
        }
        if g.degree().is_none_or(|t| t < 2) {
            return Err("g must have degree at least 2".to_string());
        }
        // Patterson's square roots need GF(2^m)[x]/g to be a field. Irreducibility also means
        // g has no roots, so every g(αᵢ) is invertible.
        if !g.is_irreducible(&field) {
            return Err(format!("{} is not irreducible", g.display(&field)));
        }

        let sys = Self::parity_check_for(&field, &support, &g).systematic();
        let k = n - sys.matrix.row_count();
        if k == 0 {
            return Err("the code has no non-zero codewords".to_string());
        }

        // Reorder the support along with the columns, so the systematic G describes this code.
        let support = sys.permutation.permute(&support);
        let generator = Matrix::identity(k).hstack(&sys.matrix.columns(0..k).transpose());

        let syndrome_terms = support
            .iter()
            .map(|&alpha| {
                Poly::from_coeffs(vec![alpha, 1])
                    .inv_mod(&g, &field)
                    .expect("x - αᵢ is coprime to an irreducible g without roots")
            })
            .collect();
        let sqrt_x = Poly::sqrt_x_mod(&g, &field);

        return Ok(Self {
            field,
            support,
            g,
            sqrt_x,
            syndrome_terms,
            generator,
        });
    }

    /// The binary (m·t) × n parity-check matrix: rows αᵢʲ/g(αᵢ) for j = 0..t, with every
    /// entry of GF(2^m) spread over m rows, bit b of the entry in row j·m + b.
    fn parity_check_for(field: &Field, support: &[Gf], g: &Poly) -> Matrix {
        let m = field.m() as usize;
        let t = g.degree().unwrap();
        let mut h = Matrix::zeros(m * t, support.len());
        for (i, &alpha) in support.iter().enumerate() {
            let mut entry = field.inv(g.eval(alpha, field));
            for j in 0..t {
                for b in 0..m {
                    h.set(j * m + b, i, entry >> b & 1 == 1);
                }
                entry = field.mul(entry, alpha);
            }
        }

        return h;
    }

    pub fn parity_check(&self) -> Matrix {
        return Self::parity_check_for(&self.field, &self.support, &self.g);
    }

    pub fn field(&self) -> &Field {
        return &self.field;
    }

    pub fn support(&self) -> &[Gf] {
        return &self.support;
    }

    pub fn g(&self) -> &Poly {
        return &self.g;
    }

    pub fn n(&self) -> usize {
        return self.support.len();
    }

    pub fn k(&self) -> usize {
        return self.generator.row_count();
    }

    pub fn t(&self) -> usize {
        return self.g.degree().unwrap();
    }

    /// k × n, of the form [I_k | Aᵀ].
    pub fn generator(&self) -> &Matrix {
        return &self.generator;
    }

    /// message·G; the codeword starts with the message itself.
    pub fn encode(&self, message: &BitVec) -> BitVec {
        return self.generator.vec_mul(message);
    }

    /// Recovers the message from a codeword of the systematic code.
    pub fn message(&self, codeword: &BitVec) -> BitVec {
        return codeword.prefix(self.k());
    }

    /// S(x) = Σ yᵢ/(x - αᵢ) mod g, zero exactly for codewords.
    pub fn syndrome(&self, y: &BitVec) -> Poly {
        let mut s = Poly::zero();
        for i in y.iter_ones() {
            s = s.add(&self.syndrome_terms[i]);
        }

        return s;
    }

    /// Patterson's algorithm: the codeword within distance t of y.
    pub fn decode(&self, y: &BitVec) -> Result<BitVec, String> {
        if y.len() != self.n() {
            return Err(format!("expected {} bits, got {}", self.n(), y.len()));
        }

        let s = self.syndrome(y);
        if s.is_zero() {
            return Ok(y.clone());
        }

        let sigma = self.error_locator(&s);
        let errors: Vec<usize> = (0..self.n())
            .filter(|&i| sigma.eval(self.support[i], &self.field) == 0)
            .collect();
        if Some(errors.len()) != sigma.degree() {
            return Err(format!("more than {} errors", self.t()));
        }

        let mut codeword = y.clone();
        for i in errors {
            codeword.flip(i);
        }
        if !self.syndrome(&codeword).is_zero() {
            return Err(format!("more than {} errors", self.t()));
        }

        return Ok(codeword);
    }

    /// σ(x) = ∏ (x - αᵢ) over the error positions, from the key equation S·σ ≡ σ' (mod g).
    fn error_locator(&self, s: &Poly) -> Poly {
        let (field, g) = (&self.field, &self.g);

        // Split σ = a² + x·b², so that σ' = b² and the key equation becomes a ≡ b·τ with
        // τ = √(S⁻¹ + x). Should S⁻¹ = x, then τ = 0 and this still yields σ = x.
        let s_inv = s
            .inv_mod(g, field)
            .expect("a non-zero syndrome is invertible modulo an irreducible g");
        let tau = s_inv
            .add(&Poly::x())
            .rem(g, field)
            .sqrt_mod(g, &self.sqrt_x, field);

        // Stopping at deg a ≤ t/2 also bounds deg b ≤ (t - 1)/2, so deg σ ≤ t.
        let (a, b) = tau.partial_ext_gcd(g, self.t() / 2, field);

        return a.square(field).add(&Poly::x().mul(&b.square(field), field));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::StdRng};

    fn rng() -> StdRng {
        return StdRng::seed_from_u64(4);
    }

    /// Encodes a random message, adds `errors` random errors and checks the round trip.
    fn check_round_trip<R: Rng>(code: &Goppa, errors: usize, rng: &mut R) {
        let message = BitVec::random(code.k(), rng);
        let codeword = code.encode(&message);
        let e = BitVec::random_with_weight(code.n(), errors, rng);
        let decoded = code.decode(&codeword.xor(&e)).unwrap();
        assert_eq!(decoded, codeword);
        assert_eq!(code.message(&decoded), message);
    }

    #[test]
    fn code_parameters() {
        let mut rng = rng();
        for (m, n, t) in [(4, 16, 2), (5, 32, 3), (8, 256, 8), (10, 1024, 50)] {
            let code = Goppa::generate(m, n, t, &mut rng).unwrap();
            assert_eq!(code.n(), n);
            assert_eq!(code.t(), t);
            assert!(code.k() >= n - m as usize * t);

            let mut sorted = code.support().to_vec();
            sorted.sort();
            sorted.dedup();
            assert_eq!(sorted.len(), n);

            // G·Hᵀ = 0, and the rows of G have zero syndrome polynomials.
            let h = code.parity_check();
            assert_eq!(
                code.generator().mul(&h.transpose()),
                Matrix::zeros(code.k(), h.row_count())
            );
            for row in code.generator().rows() {
                assert!(code.syndrome(row).is_zero());
            }
        }
    }

    #[test]
    fn corrects_up_to_t_errors() {
        let mut rng = rng();
        for (m, n, t) in [(4, 16, 2), (4, 16, 3), (5, 32, 3), (6, 60, 5), (8, 256, 8)] {
            let code = Goppa::generate(m, n, t, &mut rng).unwrap();
            for errors in 0..=t {
                for _ in 0..50 {
                    check_round_trip(&code, errors, &mut rng);
                }
            }
        }
    }

    #[test]
    fn corrects_mceliece_1978_parameters() {
        let mut rng = rng();
        let code = Goppa::generate(10, 1024, 50, &mut rng).unwrap();
        assert_eq!(code.k(), 524);
        for errors in [0, 1, 25, 49, 50] {
            check_round_trip(&code, errors, &mut rng);
        }
    }

    #[test]
    fn minimum_distance_is_at_least_2t_plus_1() {
        let mut rng = rng();
        let code = Goppa::generate(4, 16, 2, &mut rng).unwrap();
        let k = code.k();
        assert!(k <= 12, "too many codewords to enumerate");

        let min_weight = (1..1u32 << k)
            .map(|bits| {
                let mut message = BitVec::zeros(k);
                for i in (0..k).filter(|i| bits >> i & 1 == 1) {
                    message.set(i, true);
                }
                return code.encode(&message).weight();
            })
            .min()
            .unwrap();
        assert!(min_weight > 2 * code.t());
    }

    #[test]
    fn error_at_zero_support_element() {
        // An error only where αᵢ = 0 gives S = 1/x, so S⁻¹ = x: the τ = 0 case.
        let mut rng = rng();
        let code = Goppa::generate(4, 16, 2, &mut rng).unwrap();
        let zero = code.support().iter().position(|&a| a == 0).unwrap();

        let codeword = code.encode(&BitVec::random(code.k(), &mut rng));
        let mut y = codeword.clone();
        y.flip(zero);
        assert_eq!(code.decode(&y).unwrap(), codeword);

        let other = (zero + 1) % code.n();
        y.flip(other);
        assert_eq!(code.decode(&y).unwrap(), codeword);
    }

    #[test]
    fn too_many_errors_never_yield_the_original() {
        let mut rng = rng();
        let code = Goppa::generate(5, 32, 3, &mut rng).unwrap();
        let mut failures = 0;
        for _ in 0..200 {
            let codeword = code.encode(&BitVec::random(code.k(), &mut rng));
            let y = codeword.xor(&BitVec::random_with_weight(code.n(), 4, &mut rng));
            match code.decode(&y) {
                Err(_) => failures += 1,
                Ok(other) => {
                    // It can land next to another codeword, but never the sent one.
                    assert_ne!(other, codeword);
                    assert!(code.syndrome(&other).is_zero());
                    assert!(other.xor(&y).weight() <= code.t());
                }
            }
        }
        assert!(failures > 0);
    }

    #[test]
    fn from_parts_example() {
        // GF(16) with z⁴ + z + 1, all 16 elements as the support, g = x² + x + α⁷.
        let field = Field::new(4);
        let g = Poly::from_coeffs(vec![field.alpha_pow(7), 1, 1]);
        let code = Goppa::from_parts(field, (0..16).collect(), g).unwrap();
        assert_eq!(code.n(), 16);
        assert_eq!(code.k(), 8);
        assert_eq!(code.g().display(code.field()), "x^2 + x + α^7");

        let mut rng = rng();
        for errors in 0..=2 {
            check_round_trip(&code, errors, &mut rng);
        }
    }

    #[test]
    fn rejects_bad_parameters() {
        let mut rng = rng();
        assert!(Goppa::generate(1, 2, 2, &mut rng).is_err());
        assert!(Goppa::generate(17, 1000, 2, &mut rng).is_err());
        assert!(Goppa::generate(4, 17, 2, &mut rng).is_err());
        assert!(Goppa::generate(4, 16, 1, &mut rng).is_err());
        assert!(Goppa::generate(4, 16, 4, &mut rng).is_err());

        let field = Field::new(4);
        let irreducible = Poly::from_coeffs(vec![field.alpha_pow(7), 1, 1]);
        let reducible = Poly::from_coeffs(vec![field.alpha_pow(1), 1, 1]);
        assert!(
            Goppa::from_parts(
                Field::new(4),
                vec![0, 1, 1, 2, 3, 4, 5, 6, 7, 8],
                irreducible.clone()
            )
            .is_err()
        );
        assert!(Goppa::from_parts(Field::new(4), (0..16).collect(), reducible).is_err());
        assert!(Goppa::from_parts(Field::new(4), (0..16).collect(), Poly::x()).is_err());
        assert!(Goppa::from_parts(Field::new(4), vec![0, 1, 2], irreducible).is_err());

        let code = Goppa::generate(4, 16, 2, &mut rng).unwrap();
        assert!(code.decode(&BitVec::zeros(15)).is_err());
    }
}
