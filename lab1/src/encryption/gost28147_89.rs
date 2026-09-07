use std::{fmt::Display, ops::Index, vec};

use common::key::Key;
use rand::RngExt;

const BLOCK_SIZE: usize = 8;
const MAC_ITERATIONS: usize = 16;
pub const MAX_MAC_BITS: usize = 32;
const ITERATIONS: usize = 32;
const S_BLOCKS: [[u32; 16]; 8] = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12],
];
const FOUR_BIT_MASKS: [u32; 8] = [
    0x0000000F, 0x000000F0, 0x00000F00, 0x0000F000, 0x000F0000, 0x00F00000, 0x0F000000, 0xF0000000,
];

const C1: u32 = 0x01010104;
const C2: u32 = 0x01010101;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Gost28147_89Type {
    ECB,
    CTR,
    CFM,
}

impl Display for Gost28147_89Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Gost28147_89Type::ECB => "ECB",
            Gost28147_89Type::CTR => "CTR",
            Gost28147_89Type::CFM => "CFM",
        };

        return write!(f, "{name}");
    }
}

pub struct Gost28147_89 {}

impl Gost28147_89 {
    fn get_subkey(key: &Key<8>, idx: usize, encrypt: bool) -> u32 {
        if idx > 31 {
            panic!("invalid index on K_{idx}")
        }
        if encrypt {
            if idx < 24 {
                return key[idx % 8];
            } else {
                return key[(32 - (idx + 1)) % 8];
            }
        } else {
            if idx < 8 {
                return key[idx];
            } else {
                return key[7 - idx % 8];
            }
        }
    }

    fn f(half: u32, subkey: u32) -> u32 {
        let sum = half.wrapping_add(subkey);
        let mut result: u32 = 0;
        for i in 0..8 {
            let four_bits = (sum & FOUR_BIT_MASKS[i]) >> (i * 4);
            let new_four_bits: u32 = S_BLOCKS[i][four_bits as usize] << (i * 4);

            result |= new_four_bits;
        }

        return result.rotate_left(11);
    }

    fn round(a: u32, b: u32, subkey: u32) -> (u32, u32) {
        return (b ^ Self::f(a, subkey), a);
    }

    fn encrypt_block(mut a: u32, mut b: u32, key: &Key<8>, encrypt: bool) -> (u32, u32) {
        for iteration in 0..ITERATIONS {
            (a, b) = Self::round(a, b, Self::get_subkey(&key, iteration, encrypt));
        }

        return (b, a);
    }

    fn mac_block(mut a: u32, mut b: u32, key: &Key<8>) -> (u32, u32) {
        for iteration in 0..MAC_ITERATIONS {
            (a, b) = Self::round(a, b, Self::get_subkey(&key, iteration, true));
        }

        return (a, b);
    }

    fn apply_algo(bytes: Vec<u8>, key: &Key<8>, encrypt: bool) -> Vec<u8> {
        let blocks = bytes.chunks(BLOCK_SIZE);
        let mut result: Vec<u8> = vec![];

        for block in blocks {
            let a_bytes = block[0..(BLOCK_SIZE / 2)]
                .try_into()
                .expect("u32 can only be constructed from [u8;4]");
            let b_bytes = block[(BLOCK_SIZE / 2)..]
                .try_into()
                .expect("u32 can only be constructed from [u8;4]");
            let mut a = u32::from_le_bytes(a_bytes);
            let mut b = u32::from_le_bytes(b_bytes);

            (a, b) = Self::encrypt_block(a, b, key, encrypt);

            result.extend_from_slice(&a.to_le_bytes());
            result.extend_from_slice(&b.to_le_bytes());
        }

        return result;
    }

    pub fn encrypt_ecb(mut plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let padding = {
            let pd = 8 - plain_bytes.len() % 8;
            if pd == 8 { 0 } else { pd }
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
        let mut result: Vec<u8> = vec![];
        let mut rng = rand::rng();
        let s_a: u32 = rng.random();
        let s_b: u32 = rng.random();

        result.extend_from_slice(&s_a.to_le_bytes());
        result.extend_from_slice(&s_b.to_le_bytes());

        let (mut n_1, mut n_2) = Self::encrypt_block(s_a, s_b, key, true);

        let blocks = plain_bytes.chunks(BLOCK_SIZE);
        for block in blocks {
            n_1 = n_1.wrapping_add(C2);
            n_2 = {
                let (sum, carry) = n_2.overflowing_add(C1);
                sum + carry as u32
            };

            let (g_1, g_2) = Self::encrypt_block(n_1, n_2, key, true);

            let mut gamma: Vec<u8> = vec![];
            gamma.extend_from_slice(&g_1.to_le_bytes());
            gamma.extend_from_slice(&g_2.to_le_bytes());

            for (idx, byte) in block.iter().enumerate() {
                result.push(byte ^ gamma[idx]);
            }
        }

        return result;
    }

    pub fn decrypt_ctr(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];

        let s_a = u32::from_le_bytes(
            encrypted_bytes[..4]
                .try_into()
                .expect("u32 can only be constructed from [u8;4]"),
        );
        let s_b = u32::from_le_bytes(
            encrypted_bytes[4..8]
                .try_into()
                .expect("u32 can only be constructed from [u8;4]"),
        );

        let (mut n_1, mut n_2) = Self::encrypt_block(s_a, s_b, key, true);

        let blocks = encrypted_bytes[8..].chunks(BLOCK_SIZE);
        for block in blocks {
            n_1 = n_1.wrapping_add(C2);
            n_2 = {
                let (sum, carry) = n_2.overflowing_add(C1);
                sum + carry as u32
            };

            let (g_1, g_2) = Self::encrypt_block(n_1, n_2, key, true);

            let mut gamma: Vec<u8> = vec![];
            gamma.extend_from_slice(&g_1.to_le_bytes());
            gamma.extend_from_slice(&g_2.to_le_bytes());

            for (idx, byte) in block.iter().enumerate() {
                result.push(byte ^ gamma[idx]);
            }
        }

        return result;
    }

    fn split_block(block: &[u8]) -> (u32, u32) {
        let a_bytes = block[..(BLOCK_SIZE / 2)]
            .try_into()
            .expect("u32 can only be constructed from [u8;4]");
        let b_bytes = block[(BLOCK_SIZE / 2)..BLOCK_SIZE]
            .try_into()
            .expect("u32 can only be constructed from [u8;4]");

        return (u32::from_le_bytes(a_bytes), u32::from_le_bytes(b_bytes));
    }

    pub fn encrypt_cfm(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];
        let mut rng = rand::rng();
        let s_a: u32 = rng.random();
        let s_b: u32 = rng.random();

        result.extend_from_slice(&s_a.to_le_bytes());
        result.extend_from_slice(&s_b.to_le_bytes());

        let (mut n_1, mut n_2) = (s_a, s_b);

        let blocks = plain_bytes.chunks(BLOCK_SIZE);
        for block in blocks {
            let (g_1, g_2) = Self::encrypt_block(n_1, n_2, key, true);

            let mut gamma: Vec<u8> = vec![];
            gamma.extend_from_slice(&g_1.to_le_bytes());
            gamma.extend_from_slice(&g_2.to_le_bytes());

            let mut encrypted_block: Vec<u8> = Vec::with_capacity(block.len());
            for (idx, byte) in block.iter().enumerate() {
                encrypted_block.push(byte ^ gamma[idx]);
            }

            if encrypted_block.len() == BLOCK_SIZE {
                (n_1, n_2) = Self::split_block(&encrypted_block);
            }

            result.extend_from_slice(&encrypted_block);
        }

        return result;
    }

    pub fn decrypt_cfm(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let mut result: Vec<u8> = vec![];

        let (mut n_1, mut n_2) = Self::split_block(&encrypted_bytes[..BLOCK_SIZE]);

        let blocks = encrypted_bytes[BLOCK_SIZE..].chunks(BLOCK_SIZE);
        for block in blocks {
            let (g_1, g_2) = Self::encrypt_block(n_1, n_2, key, true);

            let mut gamma: Vec<u8> = vec![];
            gamma.extend_from_slice(&g_1.to_le_bytes());
            gamma.extend_from_slice(&g_2.to_le_bytes());

            for (idx, byte) in block.iter().enumerate() {
                result.push(byte ^ gamma[idx]);
            }

            if block.len() == BLOCK_SIZE {
                (n_1, n_2) = Self::split_block(block);
            }
        }

        return result;
    }

    pub fn compute_mac(mut plain_bytes: Vec<u8>, key: &Key<8>, mac_bits: usize) -> Option<u32> {
        if mac_bits == 0 || mac_bits > MAX_MAC_BITS {
            panic!("mac bits must be in 1..={MAX_MAC_BITS}, got {mac_bits}")
        }
        if plain_bytes.is_empty() {
            return None;
        }

        let padding = {
            let pd = 8 - plain_bytes.len() % 8;
            if pd == 8 { 0 } else { pd }
        };
        for _ in 0..padding {
            plain_bytes.push(0);
        }
        let (mut s_1, mut s_2) = (0u32, 0u32);

        let blocks = plain_bytes.chunks(BLOCK_SIZE);
        for block in blocks {
            let (n_1, n_2) = (
                u32::from_le_bytes(
                    block[..(BLOCK_SIZE / 2)]
                        .try_into()
                        .expect("failed to compute mac"),
                ),
                u32::from_le_bytes(
                    block[(BLOCK_SIZE / 2)..]
                        .try_into()
                        .expect("failed to compute mac"),
                ),
            );

            (s_1, s_2) = Self::mac_block(n_1 ^ s_1, n_2 ^ s_2, key);
        }

        let mac_mask: u32 = u32::MAX >> (32 - mac_bits);

        return Some(s_2 & mac_mask);
    }
}
