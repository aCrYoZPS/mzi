use super::gf::{Field, Gf, MAX_M, MIN_M};
use super::matrix::{BitVec, Matrix};
use super::poly::Poly;
use rand::Rng;
use rand::seq::SliceRandom;

pub struct Goppa {
    field: Field,
    support: Vec<Gf>,
    g: Poly,
    sqrt_x: Poly,
    syndrome_terms: Vec<Poly>,
    generator: Matrix,
}

impl Goppa {
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
        if !g.is_irreducible(&field) {
            return Err(format!("{} is not irreducible", g.display(&field)));
        }

        let sys = Self::parity_check_for(&field, &support, &g).systematic();
        let k = n - sys.matrix.row_count();
        if k == 0 {
            return Err("the code has no non-zero codewords".to_string());
        }

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

    pub fn generator(&self) -> &Matrix {
        return &self.generator;
    }

    pub fn encode(&self, message: &BitVec) -> BitVec {
        return self.generator.vec_mul(message);
    }

    pub fn message(&self, codeword: &BitVec) -> BitVec {
        return codeword.prefix(self.k());
    }

    pub fn syndrome(&self, y: &BitVec) -> Poly {
        let mut s = Poly::zero();
        for i in y.iter_ones() {
            s = s.add(&self.syndrome_terms[i]);
        }

        return s;
    }

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

    fn error_locator(&self, s: &Poly) -> Poly {
        let (field, g) = (&self.field, &self.g);

        let s_inv = s
            .inv_mod(g, field)
            .expect("a non-zero syndrome is invertible modulo an irreducible g");
        let tau = s_inv
            .add(&Poly::x())
            .rem(g, field)
            .sqrt_mod(g, &self.sqrt_x, field);

        let (a, b) = tau.partial_ext_gcd(g, self.t() / 2, field);

        return a.square(field).add(&Poly::x().mul(&b.square(field), field));
    }
}
