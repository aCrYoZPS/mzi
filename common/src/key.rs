use std::{fmt::Display, ops::Index};

#[derive(Clone, Copy)]
pub struct Key<const N: usize>(pub [u32; N]);

impl<const N: usize> Index<usize> for Key<N> {
    type Output = u32;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<const N: usize> Display for Key<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &word in &self.0 {
            write!(f, "{:08X}", word)?;
        }

        Ok(())
    }
}
