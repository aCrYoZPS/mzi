use std::{fmt::Display, ops::Index};

pub struct Stb34_101_31_2011Key(pub [u32; 8]);

impl Index<usize> for Stb34_101_31_2011Key {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Display for Stb34_101_31_2011Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &word in &self.0 {
            write!(f, "{:08X}", word)?;
        }

        Ok(())
    }
}
