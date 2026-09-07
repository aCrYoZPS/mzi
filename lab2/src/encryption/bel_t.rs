use std::fmt::Display;

use common::key::Key;

const BLOCK_SIZE: usize = 16;
const ITERATIONS: usize = 8;
const H_TABLE: [u8; 256] = [
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B, 0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
    0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B,
    0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0xB8, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99,
    0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1,
    0xC1, 0xAB, 0x76, 0x38, 0x9F, 0xE6, 0x78, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F,
    0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9E, 0xB2, 0x3D, 0x31,
    0x3E, 0x98, 0xB5, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0xB7, 0x93,
    0xE9, 0xDE, 0xE7, 0x2C, 0x8F, 0x0C, 0x0F, 0xA6, 0x2D, 0xDB, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47,
    0x06, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6,
    0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0E, 0xF2,
    0x68, 0x20, 0x80, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11,
    0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0x88, 0x5F, 0x19, 0x4B, 0x09, 0xA1,
    0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0xE8, 0x8A,
    0xA2, 0xD7, 0x46, 0x52, 0x42, 0xA8, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21,
    0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x1D,
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum BelTType {
    ECB,
    CTR,
    CFM,
}

impl Display for BelTType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            BelTType::ECB => "ECB",
            BelTType::CTR => "CTR",
            BelTType::CFM => "CFM",
        };

        return write!(f, "{name}");
    }
}

pub struct BelT {}

impl BelT {
    fn split_u128_le(n: u128) -> [u32; 4] {
        return [
            n as u32,
            (n >> 32) as u32,
            (n >> 64) as u32,
            (n >> 96) as u32,
        ];
    }

    fn g(r: u32, u: u32) -> u32 {
        return u32::from_le_bytes(u.to_le_bytes().map(|byte| H_TABLE[byte as usize]))
            .rotate_left(r);
    }

    fn get_subkey(key: &Key<8>, idx: u32) -> u32 {
        return key[(idx % 8) as usize];
    }

    fn encrypt_block(block: u128, key: &Key<8>) -> u128 {
        let [mut a, mut b, mut c, mut d] = Self::split_u128_le(block);
        for iteration in 0..ITERATIONS {
            let i = (iteration + 1) as u32;
            b = b ^ Self::g(5, a.wrapping_add(Self::get_subkey(key, (7 * i - 6) - 1)));
            c = c ^ Self::g(21, d.wrapping_add(Self::get_subkey(key, (7 * i - 5) - 1)));
            a = a.wrapping_sub(Self::g(
                13,
                b.wrapping_add(Self::get_subkey(key, (7 * i - 4) - 1)),
            ));
            let e = i ^ Self::g(
                21,
                b.wrapping_add(c)
                    .wrapping_add(Self::get_subkey(key, (7 * i - 3) - 1)),
            );
            b = b.wrapping_add(e);
            c = c.wrapping_sub(e);
            d = d.wrapping_add(Self::g(
                13,
                c.wrapping_add(Self::get_subkey(key, (7 * i - 2) - 1)),
            ));
            b = b ^ Self::g(21, a.wrapping_add(Self::get_subkey(key, (7 * i - 1) - 1)));
            c = c ^ Self::g(5, d.wrapping_add(Self::get_subkey(key, (7 * i) - 1)));
            (a, b) = (b, a);
            (c, d) = (d, c);
            (b, c) = (c, b);
        }

        return (c as u128) << 96 | (a as u128) << 64 | (d as u128) << 32 | (b as u128);
    }

    fn decrypt_block(block: u128, key: &Key<8>) -> u128 {
        let [mut a, mut b, mut c, mut d] = Self::split_u128_le(block);

        for iteration in (0..ITERATIONS).rev() {
            let i = (iteration + 1) as u32;
            b = b ^ Self::g(5, a.wrapping_add(Self::get_subkey(key, (7 * i) - 1)));
            c = c ^ Self::g(21, d.wrapping_add(Self::get_subkey(key, (7 * i - 1) - 1)));
            a = a.wrapping_sub(Self::g(
                13,
                b.wrapping_add(Self::get_subkey(key, (7 * i - 2) - 1)),
            ));
            let e = i ^ Self::g(
                21,
                b.wrapping_add(c)
                    .wrapping_add(Self::get_subkey(key, (7 * i - 3) - 1)),
            );
            b = b.wrapping_add(e);
            c = c.wrapping_sub(e);
            d = d.wrapping_add(Self::g(
                13,
                c.wrapping_add(Self::get_subkey(key, (7 * i - 4) - 1)),
            ));
            b = b ^ Self::g(21, a.wrapping_add(Self::get_subkey(key, (7 * i - 5) - 1)));
            c = c ^ Self::g(5, d.wrapping_add(Self::get_subkey(key, (7 * i - 6) - 1)));
            (a, b) = (b, a);
            (c, d) = (d, c);
            (a, d) = (d, a);
        }

        return (b as u128) << 96 | (d as u128) << 64 | (a as u128) << 32 | (c as u128);
    }

    fn block_from(bytes: &[u8]) -> u128 {
        return u128::from_le_bytes(
            bytes
                .try_into()
                .expect("u128 can only be constructed from [u8;16]"),
        );
    }

    fn apply_algo(bytes: Vec<u8>, key: &Key<8>, encrypt: bool) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::with_capacity(bytes.len());

        for block in bytes.chunks(BLOCK_SIZE) {
            let n = Self::block_from(block);
            let processed = if encrypt {
                Self::encrypt_block(n, key)
            } else {
                Self::decrypt_block(n, key)
            };

            result.extend_from_slice(&processed.to_le_bytes());
        }

        return result;
    }

    pub fn encrypt_ecb(mut plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let padding = {
            let pd = BLOCK_SIZE - plain_bytes.len() % BLOCK_SIZE;
            if pd == BLOCK_SIZE { 0 } else { pd }
        };
        for _ in 0..padding {
            plain_bytes.push(0);
        }

        let mut result = Self::apply_algo(plain_bytes, key, true);
        result.push(padding as u8);

        return result;
    }

    pub fn decrypt_ecb(mut encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let padding = encrypted_bytes.pop().unwrap_or(0) as usize;

        let mut result = Self::apply_algo(encrypted_bytes, key, false);
        for _ in 0..padding {
            result.pop();
        }

        return result;
    }

    pub fn encrypt_ctr(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        todo!()
    }

    pub fn decrypt_ctr(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        todo!()
    }

    pub fn encrypt_cfm(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        todo!()
    }

    pub fn decrypt_cfm(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        todo!()
    }
}
