use super::gf::{Field, Gf};
use rand::Rng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    coeffs: Vec<Gf>,
}

impl Poly {
    pub fn zero() -> Self {
        return Self { coeffs: vec![] };
    }

    pub fn one() -> Self {
        return Self::constant(1);
    }

    pub fn x() -> Self {
        return Self::monomial(1, 1);
    }

    pub fn constant(c: Gf) -> Self {
        return Self::from_coeffs(vec![c]);
    }

    pub fn monomial(c: Gf, degree: usize) -> Self {
        let mut coeffs = vec![0; degree + 1];
        coeffs[degree] = c;

        return Self::from_coeffs(coeffs);
    }

    pub fn from_coeffs(coeffs: Vec<Gf>) -> Self {
        let mut poly = Self { coeffs };
        poly.normalize();

        return poly;
    }

    fn normalize(&mut self) {
        while self.coeffs.last() == Some(&0) {
            self.coeffs.pop();
        }
    }

    pub fn coeffs(&self) -> &[Gf] {
        return &self.coeffs;
    }

    pub fn coeff(&self, i: usize) -> Gf {
        return self.coeffs.get(i).copied().unwrap_or(0);
    }

    pub fn degree(&self) -> Option<usize> {
        return self.coeffs.len().checked_sub(1);
    }

    pub fn is_zero(&self) -> bool {
        return self.coeffs.is_empty();
    }

    pub fn leading(&self) -> Gf {
        return self.coeffs.last().copied().unwrap_or(0);
    }

    pub fn is_monic(&self) -> bool {
        return self.leading() == 1;
    }

    pub fn add(&self, other: &Poly) -> Poly {
        let (long, short) = if self.coeffs.len() >= other.coeffs.len() {
            (self, other)
        } else {
            (other, self)
        };
        let mut coeffs = long.coeffs.clone();
        for (c, &s) in coeffs.iter_mut().zip(&short.coeffs) {
            *c ^= s;
        }

        return Self::from_coeffs(coeffs);
    }

    pub fn scale(&self, c: Gf, field: &Field) -> Poly {
        return Self::from_coeffs(self.coeffs.iter().map(|&a| field.mul(a, c)).collect());
    }

    pub fn mul(&self, other: &Poly, field: &Field) -> Poly {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }

        let mut coeffs = vec![0; self.coeffs.len() + other.coeffs.len() - 1];
        for (i, &a) in self.coeffs.iter().enumerate() {
            if a == 0 {
                continue;
            }
            for (j, &b) in other.coeffs.iter().enumerate() {
                coeffs[i + j] ^= field.mul(a, b);
            }
        }

        return Self::from_coeffs(coeffs);
    }

    pub fn square(&self, field: &Field) -> Poly {
        let mut coeffs = vec![0; (2 * self.coeffs.len()).saturating_sub(1)];
        for (i, &c) in self.coeffs.iter().enumerate() {
            coeffs[2 * i] = field.square(c);
        }

        return Self::from_coeffs(coeffs);
    }

    pub fn div_rem(&self, divisor: &Poly, field: &Field) -> (Poly, Poly) {
        let divisor_degree = divisor.degree().expect("division by the zero polynomial");
        if self.coeffs.len() <= divisor_degree {
            return (Self::zero(), self.clone());
        }

        let leading_inv = field.inv(divisor.leading());
        let mut rem = self.coeffs.clone();
        let mut quot = vec![0; rem.len() - divisor_degree];
        for i in (0..quot.len()).rev() {
            let c = field.mul(rem[i + divisor_degree], leading_inv);
            if c == 0 {
                continue;
            }
            quot[i] = c;
            for (j, &d) in divisor.coeffs.iter().enumerate() {
                rem[i + j] ^= field.mul(c, d);
            }
        }
        rem.truncate(divisor_degree);

        return (Self::from_coeffs(quot), Self::from_coeffs(rem));
    }

    pub fn rem(&self, modulus: &Poly, field: &Field) -> Poly {
        return self.div_rem(modulus, field).1;
    }

    pub fn eval(&self, x: Gf, field: &Field) -> Gf {
        return self
            .coeffs
            .iter()
            .rev()
            .fold(0, |acc, &c| field.mul(acc, x) ^ c);
    }

    pub fn monic(&self, field: &Field) -> Poly {
        if self.is_zero() {
            return Self::zero();
        }

        return self.scale(field.inv(self.leading()), field);
    }

    pub fn gcd(&self, other: &Poly, field: &Field) -> Poly {
        let mut a = self.clone();
        let mut b = other.clone();
        while !b.is_zero() {
            let r = a.rem(&b, field);
            a = b;
            b = r;
        }

        return a.monic(field);
    }

    pub fn mul_mod(&self, other: &Poly, modulus: &Poly, field: &Field) -> Poly {
        return self.mul(other, field).rem(modulus, field);
    }

    pub fn square_mod(&self, modulus: &Poly, field: &Field) -> Poly {
        return self.square(field).rem(modulus, field);
    }

    pub fn inv_mod(&self, modulus: &Poly, field: &Field) -> Option<Poly> {
        let (mut r0, mut r1) = (modulus.clone(), self.rem(modulus, field));
        let (mut v0, mut v1) = (Self::zero(), Self::one());
        while !r1.is_zero() {
            let (q, r) = r0.div_rem(&r1, field);
            let v = v0.add(&q.mul(&v1, field));
            (r0, r1) = (r1, r);
            (v0, v1) = (v1, v);
        }
        if r0.degree() != Some(0) {
            return None;
        }

        return Some(v0.scale(field.inv(r0.leading()), field).rem(modulus, field));
    }

    pub fn partial_ext_gcd(
        &self,
        modulus: &Poly,
        stop_degree: usize,
        field: &Field,
    ) -> (Poly, Poly) {
        let (mut r0, mut r1) = (modulus.clone(), self.rem(modulus, field));
        let (mut v0, mut v1) = (Self::zero(), Self::one());
        while r1.degree().is_some_and(|d| d > stop_degree) {
            let (q, r) = r0.div_rem(&r1, field);
            let v = v0.add(&q.mul(&v1, field));
            (r0, r1) = (r1, r);
            (v0, v1) = (v1, v);
        }

        return (r1, v1);
    }

    pub fn sqrt_x_mod(modulus: &Poly, field: &Field) -> Poly {
        let t = modulus.degree().expect("modulus must not be zero");
        let mut root = Self::x().rem(modulus, field);
        for _ in 1..field.m() as usize * t {
            root = root.square_mod(modulus, field);
        }

        return root;
    }

    pub fn sqrt_mod(&self, modulus: &Poly, sqrt_x: &Poly, field: &Field) -> Poly {
        let roots: Vec<Gf> = self.coeffs.iter().map(|&c| field.sqrt(c)).collect();
        let even = Self::from_coeffs(roots.iter().step_by(2).copied().collect());
        let odd = Self::from_coeffs(roots.iter().skip(1).step_by(2).copied().collect());

        return even.add(&sqrt_x.mul(&odd, field)).rem(modulus, field);
    }

    pub fn is_irreducible(&self, field: &Field) -> bool {
        let n = match self.degree() {
            None | Some(0) => return false,
            Some(n) => n,
        };

        let x = Self::x().rem(self, field);
        let mut h = x.clone();
        for _ in 0..n / 2 {
            for _ in 0..field.m() {
                h = h.square_mod(self, field);
            }
            if self.gcd(&h.add(&x), field).degree() != Some(0) {
                return false;
            }
        }

        return true;
    }

    pub fn random_monic<R: Rng>(degree: usize, rng: &mut R, field: &Field) -> Poly {
        let mut coeffs: Vec<Gf> = (0..degree).map(|_| field.random(rng)).collect();
        coeffs.push(1);

        return Self::from_coeffs(coeffs);
    }

    pub fn random_irreducible<R: Rng>(degree: usize, rng: &mut R, field: &Field) -> Poly {
        assert!(
            degree >= 1,
            "irreducible polynomials have degree at least 1"
        );
        loop {
            let candidate = Self::random_monic(degree, rng, field);
            if candidate.is_irreducible(field) {
                return candidate;
            }
        }
    }

    pub fn display(&self, field: &Field) -> String {
        if self.is_zero() {
            return "0".to_string();
        }

        let terms: Vec<String> = self
            .coeffs
            .iter()
            .enumerate()
            .rev()
            .filter(|&(_, &c)| c != 0)
            .map(|(i, &c)| {
                let power = match i {
                    0 => String::new(),
                    1 => "x".to_string(),
                    _ => format!("x^{i}"),
                };
                return match (c, i) {
                    (_, 0) => field.display(c),
                    (1, _) => power,
                    _ => format!("{}·{power}", field.display(c)),
                };
            })
            .collect();

        return terms.join(" + ");
    }
}
