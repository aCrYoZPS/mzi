use rand::Rng;

pub type Gf = u16;

pub const MIN_M: u32 = 2;
pub const MAX_M: u32 = 16;

const PRIMITIVE_POLYNOMIALS: [u32; 15] = [
    0x7, 0xB, 0x13, 0x25, 0x43, 0x83, 0x11D, 0x211, 0x409, 0x805, 0x1053, 0x201B, 0x4443, 0x8003,
    0x1100B,
];

pub struct Field {
    m: u32,
    modulus: u32,
    exp: Vec<Gf>,
    log: Vec<u32>,
}

impl Field {
    pub fn new(m: u32) -> Self {
        assert!(
            (MIN_M..=MAX_M).contains(&m),
            "m must be in {MIN_M}..={MAX_M}"
        );

        return Self::with_modulus(m, PRIMITIVE_POLYNOMIALS[(m - MIN_M) as usize])
            .expect("the built-in polynomials are primitive");
    }

    pub fn with_modulus(m: u32, modulus: u32) -> Result<Self, String> {
        if !(MIN_M..=MAX_M).contains(&m) {
            return Err(format!("m must be in {MIN_M}..={MAX_M}"));
        }
        if modulus >> m != 1 {
            return Err(format!("{modulus:#b} is not a polynomial of degree {m}"));
        }

        let order = (1usize << m) - 1;
        let mut exp = vec![0; 2 * order];
        let mut log = vec![0; order + 1];
        let mut seen = vec![false; order + 1];

        let mut a: u32 = 1;
        for i in 0..order {
            if a == 0 || seen[a as usize] {
                return Err(format!("{modulus:#b} is not primitive"));
            }
            seen[a as usize] = true;
            exp[i] = a as Gf;
            exp[i + order] = a as Gf;
            log[a as usize] = i as u32;

            a <<= 1;
            if a >> m != 0 {
                a ^= modulus;
            }
        }
        if a != 1 {
            return Err(format!("{modulus:#b} is not primitive"));
        }

        return Ok(Self {
            m,
            modulus,
            exp,
            log,
        });
    }

    pub fn m(&self) -> u32 {
        return self.m;
    }

    pub fn modulus(&self) -> u32 {
        return self.modulus;
    }

    pub fn size(&self) -> usize {
        return 1 << self.m;
    }

    pub fn order(&self) -> usize {
        return self.size() - 1;
    }

    pub fn add(&self, a: Gf, b: Gf) -> Gf {
        return a ^ b;
    }

    pub fn mul(&self, a: Gf, b: Gf) -> Gf {
        if a == 0 || b == 0 {
            return 0;
        }

        return self.exp[(self.log[a as usize] + self.log[b as usize]) as usize];
    }

    pub fn inv(&self, a: Gf) -> Gf {
        assert!(a != 0, "zero has no inverse");

        return self.exp[(self.order() - self.log[a as usize] as usize) % self.order()];
    }

    pub fn div(&self, a: Gf, b: Gf) -> Gf {
        return self.mul(a, self.inv(b));
    }

    pub fn square(&self, a: Gf) -> Gf {
        return self.mul(a, a);
    }

    pub fn sqrt(&self, a: Gf) -> Gf {
        if a == 0 {
            return 0;
        }

        let exponent = self.log[a as usize] as u64 * (1 << (self.m - 1)) % self.order() as u64;

        return self.exp[exponent as usize];
    }

    pub fn pow(&self, a: Gf, e: u64) -> Gf {
        if a == 0 {
            return if e == 0 { 1 } else { 0 };
        }

        let order = self.order() as u64;
        let exponent = self.log[a as usize] as u64 * (e % order) % order;

        return self.exp[exponent as usize];
    }

    pub fn alpha_pow(&self, i: usize) -> Gf {
        return self.exp[i % self.order()];
    }

    pub fn log(&self, a: Gf) -> Option<u32> {
        if a == 0 {
            return None;
        }

        return Some(self.log[a as usize]);
    }

    pub fn random<R: Rng>(&self, rng: &mut R) -> Gf {
        return rng.gen_range(0..self.size()) as Gf;
    }

    pub fn random_nonzero<R: Rng>(&self, rng: &mut R) -> Gf {
        return rng.gen_range(1..self.size()) as Gf;
    }

    pub fn display(&self, a: Gf) -> String {
        return match self.log(a) {
            None => "0".to_string(),
            Some(0) => "1".to_string(),
            Some(1) => "α".to_string(),
            Some(i) => format!("α^{i}"),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mul_reference(a: Gf, b: Gf, m: u32, modulus: u32) -> Gf {
        let mut a = a as u32;
        let mut b = b as u32;
        let mut result = 0;
        while b != 0 {
            if b & 1 == 1 {
                result ^= a;
            }
            b >>= 1;
            a <<= 1;
            if a >> m != 0 {
                a ^= modulus;
            }
        }

        return result as Gf;
    }

    #[test]
    fn built_in_polynomials_are_primitive() {
        for m in MIN_M..=MAX_M {
            let field = Field::new(m);
            assert_eq!(field.size(), 1 << m);
            assert_eq!(field.alpha_pow(field.order()), 1);
        }
    }

    #[test]
    fn rejects_bad_moduli() {
        assert!(Field::with_modulus(4, 0b11111).is_err());
        assert!(Field::with_modulus(4, 0b10101).is_err());
        assert!(Field::with_modulus(4, 0b11000).is_err());
        assert!(Field::with_modulus(4, 0b1011).is_err());
        assert!(Field::with_modulus(4, 0b10011).is_ok());
    }

    #[test]
    fn mul_matches_reference() {
        for m in [4, 8] {
            let field = Field::new(m);
            for a in 0..field.size() as Gf {
                for b in 0..field.size() as Gf {
                    assert_eq!(field.mul(a, b), mul_reference(a, b, m, field.modulus()));
                }
            }
        }
    }

    #[test]
    fn distributive() {
        let field = Field::new(4);
        for a in 0..16 {
            for b in 0..16 {
                for c in 0..16 {
                    assert_eq!(
                        field.mul(a, field.add(b, c)),
                        field.add(field.mul(a, b), field.mul(a, c))
                    );
                }
            }
        }
    }

    #[test]
    fn inverse_and_division() {
        let field = Field::new(8);
        for a in 1..field.size() as Gf {
            assert_eq!(field.mul(a, field.inv(a)), 1);
            for b in [1, 2, 0x53, 0xFF] {
                assert_eq!(field.mul(field.div(a, b), b), a);
            }
        }
    }

    #[test]
    fn sqrt_inverts_square() {
        for m in [4, 8, 13] {
            let field = Field::new(m);
            for a in 0..field.size() as Gf {
                assert_eq!(field.square(field.sqrt(a)), a);
                assert_eq!(field.sqrt(field.square(a)), a);
            }
        }
    }

    #[test]
    fn pow() {
        let field = Field::new(8);
        assert_eq!(field.pow(0, 0), 1);
        assert_eq!(field.pow(0, 5), 0);
        for a in 1..field.size() as Gf {
            assert_eq!(field.pow(a, 0), 1);
            assert_eq!(field.pow(a, 1), a);
            assert_eq!(field.pow(a, 2), field.square(a));
            assert_eq!(field.pow(a, 3), field.mul(a, field.square(a)));
            assert_eq!(field.pow(a, field.order() as u64), 1);
        }
    }

    #[test]
    fn display() {
        let field = Field::new(4);
        assert_eq!(field.display(0), "0");
        assert_eq!(field.display(1), "1");
        assert_eq!(field.display(0b10), "α");
        assert_eq!(field.display(0b1011), "α^7");
    }
}
