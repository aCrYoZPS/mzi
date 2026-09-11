use std::fmt::Display;

use common::key::Key;
use rand::random;

const BLOCK_SIZE: usize = 16;
const ITERATIONS: usize = 8;
pub const MAX_MAC_BITS: usize = 64;
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
    CBC,
    CTR,
    CFM,
}

impl Display for BelTType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            BelTType::ECB => "ECB",
            BelTType::CBC => "CBC",
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

    fn apply_ecb(bytes: Vec<u8>, key: &Key<8>, encrypt: bool) -> Vec<u8> {
        assert!(
            bytes.len() >= BLOCK_SIZE,
            "belt-ecb needs at least one whole block"
        );

        let full = bytes.len() / BLOCK_SIZE;
        let rest = bytes.len() % BLOCK_SIZE;

        let apply = |n: u128| {
            if encrypt {
                Self::encrypt_block(n, key)
            } else {
                Self::decrypt_block(n, key)
            }
        };

        let mut result: Vec<u8> = Vec::with_capacity(bytes.len());

        for (idx, block) in bytes.chunks(BLOCK_SIZE).enumerate() {
            if idx == full {
                break;
            }

            let n = Self::block_from(block);
            let processed = apply(n);
            result.extend_from_slice(&processed.to_le_bytes());
        }

        if rest != 0 {
            let second_to_last_block_start = (full - 1) * BLOCK_SIZE;
            let last_block_start = full * BLOCK_SIZE;
            result.resize(result.len() + rest, 0);
            result[last_block_start..].copy_from_slice(&bytes[last_block_start..]);
            for j in 0..rest {
                result.swap(last_block_start + j, second_to_last_block_start + j);
            }
            let processed = apply(Self::block_from(
                &result[second_to_last_block_start..last_block_start],
            ));
            result[second_to_last_block_start..last_block_start]
                .copy_from_slice(&processed.to_le_bytes());
        }

        return result;
    }

    pub fn encrypt_ecb(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        return Self::apply_ecb(plain_bytes, key, true);
    }

    pub fn decrypt_ecb(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        return Self::apply_ecb(encrypted_bytes, key, false);
    }

    fn apply_cbc(bytes: &[u8], key: &Key<8>, sync: u128, encrypt: bool) -> Vec<u8> {
        assert!(
            bytes.len() >= BLOCK_SIZE,
            "belt-cbc needs at least one whole block"
        );

        let full = bytes.len() / BLOCK_SIZE;
        let rest = bytes.len() % BLOCK_SIZE;
        let chained = if rest == 0 { full } else { full - 1 };

        let apply = |n: u128| {
            if encrypt {
                Self::encrypt_block(n, key)
            } else {
                Self::decrypt_block(n, key)
            }
        };

        let mut prev: u128 = sync;
        let mut result: Vec<u8> = Vec::with_capacity(bytes.len());

        for block in bytes.chunks_exact(BLOCK_SIZE).take(chained) {
            let x = Self::block_from(block);
            let y = if encrypt {
                apply(x ^ prev)
            } else {
                apply(x) ^ prev
            };
            result.extend_from_slice(&y.to_le_bytes());

            prev = if encrypt { y } else { x };
        }

        if rest == 0 {
            return result;
        }

        let second_to_last_block_start = (full - 1) * BLOCK_SIZE;
        let last_block_start = full * BLOCK_SIZE;

        let x_n_m_1 = Self::block_from(&bytes[second_to_last_block_start..last_block_start]);

        let mut x_n_buf = [0u8; BLOCK_SIZE];
        x_n_buf[..rest].copy_from_slice(&bytes[last_block_start..]);
        let x_n = Self::block_from(&x_n_buf);

        let y_n_r = if encrypt {
            apply(x_n_m_1 ^ prev)
        } else {
            apply(x_n_m_1) ^ x_n
        };

        let rest_bits = rest * 8;
        let y_n = y_n_r & (u128::MAX >> (128 - rest_bits));
        let r = y_n_r >> rest_bits;

        let combined = if encrypt {
            (x_n ^ y_n) | (r << rest_bits)
        } else {
            x_n | (r << rest_bits)
        };

        let y_n_m_1 = if encrypt {
            apply(combined)
        } else {
            apply(combined) ^ prev
        };

        result.extend_from_slice(&y_n_m_1.to_le_bytes());
        result.extend_from_slice(&y_n.to_le_bytes()[..rest]);

        return result;
    }

    pub fn encrypt_cbc(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let sync: u128 = random();

        let mut result: Vec<u8> = Vec::with_capacity(BLOCK_SIZE + plain_bytes.len());
        result.extend_from_slice(&sync.to_le_bytes());
        result.extend_from_slice(&Self::apply_cbc(&plain_bytes, key, sync, true));

        return result;
    }

    pub fn decrypt_cbc(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let (sync, body) = encrypted_bytes.split_at(BLOCK_SIZE);

        return Self::apply_cbc(body, key, Self::block_from(sync), false);
    }

    fn l(bits: usize, n: u128) -> u128 {
        return n & (u128::MAX >> (128 - bits));
    }

    fn apply_ctr(bytes: &[u8], key: &Key<8>, sync: u128) -> Vec<u8> {
        let full = bytes.len() / BLOCK_SIZE;
        let rest = bytes.len() % BLOCK_SIZE;

        let apply = |n: u128| Self::encrypt_block(n, key);

        let mut s: u128 = apply(sync);
        let mut result: Vec<u8> = Vec::with_capacity(bytes.len());

        for block in bytes.chunks_exact(BLOCK_SIZE) {
            s = s.wrapping_add(1);
            let x = Self::block_from(block);
            let y = x ^ apply(s);
            result.extend_from_slice(&y.to_le_bytes());
        }

        if rest != 0 {
            let last_block_start = full * BLOCK_SIZE;
            let mut x_n_buf = [0u8; BLOCK_SIZE];
            x_n_buf[..rest].copy_from_slice(&bytes[last_block_start..]);
            let x_n = Self::block_from(&x_n_buf);

            s = s.wrapping_add(1);

            let processed = x_n ^ Self::l(rest * 8, apply(s));

            result.extend_from_slice(&processed.to_le_bytes()[..rest]);
        }

        return result;
    }

    pub fn encrypt_ctr(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let sync: u128 = random();

        let mut result: Vec<u8> = Vec::with_capacity(BLOCK_SIZE + plain_bytes.len());
        result.extend_from_slice(&sync.to_le_bytes());
        result.extend_from_slice(&Self::apply_ctr(&plain_bytes, key, sync));

        return result;
    }

    pub fn decrypt_ctr(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let (sync, body) = encrypted_bytes.split_at(BLOCK_SIZE);

        return Self::apply_ctr(body, key, Self::block_from(sync));
    }

    fn apply_cfm(bytes: &[u8], key: &Key<8>, sync: u128, encrypt: bool) -> Vec<u8> {
        let full = bytes.len() / BLOCK_SIZE;
        let rest = bytes.len() % BLOCK_SIZE;

        let apply = |n: u128| Self::encrypt_block(n, key);

        let mut prev: u128 = sync;
        let mut result: Vec<u8> = Vec::with_capacity(bytes.len());

        for block in bytes.chunks_exact(BLOCK_SIZE) {
            let x = Self::block_from(block);
            let y = x ^ apply(prev);
            result.extend_from_slice(&y.to_le_bytes());
            prev = if encrypt { y } else { x };
        }

        if rest != 0 {
            let last_block_start = full * BLOCK_SIZE;
            let mut x_n_buf = [0u8; BLOCK_SIZE];
            x_n_buf[..rest].copy_from_slice(&bytes[last_block_start..]);
            let x_n = Self::block_from(&x_n_buf);
            let processed = x_n ^ Self::l(rest * 8, apply(prev));

            result.extend_from_slice(&processed.to_le_bytes()[..rest]);
        }

        return result;
    }

    pub fn encrypt_cfm(plain_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let sync: u128 = random();

        let mut result: Vec<u8> = Vec::with_capacity(BLOCK_SIZE + plain_bytes.len());
        result.extend_from_slice(&sync.to_le_bytes());
        result.extend_from_slice(&Self::apply_cfm(&plain_bytes, key, sync, true));

        return result;
    }

    pub fn decrypt_cfm(encrypted_bytes: Vec<u8>, key: &Key<8>) -> Vec<u8> {
        let (sync, body) = encrypted_bytes.split_at(BLOCK_SIZE);

        return Self::apply_cfm(body, key, Self::block_from(sync), false);
    }

    fn phi_1(u: u128) -> u128 {
        let (u1, u2, u3, u4) = (
            u as u32,
            (u >> 32) as u32,
            (u >> 64) as u32,
            (u >> 96) as u32,
        );

        return ((u1 ^ u2) as u128) << 96 | (u4 as u128) << 64 | (u3 as u128) << 32 | u2 as u128;
    }

    fn phi_2(u: u128) -> u128 {
        let (u1, u2, u3, u4) = (
            u as u32,
            (u >> 32) as u32,
            (u >> 64) as u32,
            (u >> 96) as u32,
        );

        return (u3 as u128) << 96 | (u2 as u128) << 64 | (u1 as u128) << 32 | (u1 ^ u4) as u128;
    }

    fn psi(u: u128, word_len_bits: usize) -> u128 {
        return u | (1 << (word_len_bits + 7));
    }

    fn truncate_mac(s: u128, mac_bits: usize) -> u64 {
        let tag = u64::from_be_bytes(
            s.to_le_bytes()[..8]
                .try_into()
                .expect("a block always has 16 bytes"),
        );

        return tag >> (64 - mac_bits);
    }

    pub fn compute_mac(message: Vec<u8>, key: &Key<8>, mac_bits: usize) -> Option<u64> {
        assert!(
            (1..=MAX_MAC_BITS).contains(&mac_bits),
            "mac bits must be in 1..={MAX_MAC_BITS}, got {mac_bits}"
        );

        let whole_tail = !message.is_empty() && message.len() % BLOCK_SIZE == 0;
        let head_blocks = message.len() / BLOCK_SIZE - whole_tail as usize;

        let apply = |n: u128| Self::encrypt_block(n, key);
        let mut s = 0u128;
        let r = apply(s);

        for block in message.chunks_exact(BLOCK_SIZE).take(head_blocks) {
            s = apply(s ^ Self::block_from(block));
        }

        let tail = &message[head_blocks * BLOCK_SIZE..];
        let mut x_n_buf = [0u8; BLOCK_SIZE];
        x_n_buf[..tail.len()].copy_from_slice(tail);
        let x_n = Self::block_from(&x_n_buf);

        s = if whole_tail {
            s ^ x_n ^ Self::phi_1(r)
        } else {
            s ^ Self::psi(x_n, tail.len() * 8) ^ Self::phi_2(r)
        };

        return Some(Self::truncate_mac(apply(s), mac_bits));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::cli::{from_hex, parse_key};

    const K1: &str = "E9DEE72C8F0C0FA62DDB49F46F739647 06075316ED247A3739CBA38303A98BF6";
    const K2: &str = "92BD9B1CE5D141015445FBC95E4D0EF2 682080AA227D642F2687F93490405511";
    const S1: &str = "BE32971343FC9A48A02A885F194B09A1";
    const S2: &str = "7ECDA4D01544AF8CA58450BF66D2E88A";

    fn bytes(hex: &str) -> Vec<u8> {
        return from_hex(hex).expect("a test vector must be valid hex");
    }

    fn key(hex: &str) -> Key<8> {
        return parse_key(&hex.replace(' ', "")).expect("a test key must be 64 hex digits");
    }

    fn block(hex: &str) -> u128 {
        return BelT::block_from(&bytes(hex));
    }

    #[test]
    fn ecb_encrypt_whole_blocks() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D61217B96181FE6786AD716B890B",
        );
        let y = bytes(
            "69CCA1C93557C9E3D66BC3E0FA88FA6E 5F23102EF1097107 75017F73806DA9DC
             46FB2ED2CE771F26DCB5E5D1569F9AB0",
        );

        assert_eq!(BelT::encrypt_ecb(x, &key(K1)), y);
    }

    #[test]
    fn ecb_encrypt_partial_block() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D61217B96181FE6786AD716B89",
        );
        let y = bytes(
            "69CCA1C93557C9E3D66BC3E0FA88FA6E 36F00CFED6D1CA1498C12798F4BEB207
             5F23102EF109710775017F73806DA9",
        );

        assert_eq!(BelT::encrypt_ecb(x, &key(K1)), y);
    }

    #[test]
    fn ecb_decrypt_whole_blocks() {
        let y = bytes(
            "E12BDC1AE28257EC703FCCF095EE8DF1 C1AB76389FE678CAF7C6F860D5BB9C4F
             F33C657B637C306ADD4EA7799EB23D31",
        );
        let x = bytes(
            "0DC5300600CAB840B38448E5E993F421 E55A239F2AB5C5D5FDB6E81B40938E2A
             54120CA3E6E19C7AD750FC3531DAEAB7",
        );

        assert_eq!(BelT::decrypt_ecb(y, &key(K2)), x);
    }

    #[test]
    fn ecb_decrypt_partial_block() {
        let y = bytes(
            "E12BDC1AE28257EC703FCCF095EE8DF1 C1AB76389FE678CAF7C6F860D5BB9C4F
             F33C657B",
        );
        let x = bytes(
            "0DC5300600CAB840B38448E5E993F421 5780A6E2B69EAFBB258726D7B6718523
             E55A239F",
        );

        assert_eq!(BelT::decrypt_ecb(y, &key(K2)), x);
    }

    #[test]
    fn block_transform() {
        assert_eq!(
            BelT::encrypt_block(block("B194BAC80A08F53B366D008E584A5DE4"), &key(K1)),
            block("69CCA1C93557C9E3D66BC3E0FA88FA6E")
        );
        assert_eq!(
            BelT::decrypt_block(block("E12BDC1AE28257EC703FCCF095EE8DF1"), &key(K2)),
            block("0DC5300600CAB840B38448E5E993F421")
        );
    }

    #[test]
    fn cbc_encrypt_whole_blocks() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D61217B96181FE6786AD716B890B",
        );
        let y = bytes(
            "10116EFAE6AD58EE14852E11DA1B8A74 5CF2480E8D03F1C19492E53ED3A70F60
             657C1EE8C0E0AE5B58388BF8A68E3309",
        );

        assert_eq!(BelT::apply_cbc(&x, &key(K1), block(S1), true), y);
    }

    #[test]
    fn cbc_encrypt_partial_block() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D612",
        );
        let y = bytes(
            "10116EFAE6AD58EE14852E11DA1B8A74 6A9BBADCAF73F968F875DEDC0A44F6B1
             5CF2480E",
        );

        assert_eq!(BelT::apply_cbc(&x, &key(K1), block(S1), true), y);
    }

    #[test]
    fn cbc_decrypt_whole_blocks() {
        let y = bytes(
            "E12BDC1AE28257EC703FCCF095EE8DF1 C1AB76389FE678CAF7C6F860D5BB9C4F
             F33C657B637C306ADD4EA7799EB23D31",
        );
        let x = bytes(
            "730894D6158E17CC1600185A8F411CAB 0471FF85C83792398D8924EBD57D03DB
             95B97A9B7907E4B020960455E46176F8",
        );

        assert_eq!(BelT::apply_cbc(&y, &key(K2), block(S2), false), x);
    }

    #[test]
    fn cbc_decrypt_partial_block() {
        let y = bytes(
            "E12BDC1AE28257EC703FCCF095EE8DF1 C1AB76389FE678CAF7C6F860D5BB9C4F
             F33C657B",
        );
        let x = bytes(
            "730894D6158E17CC1600185A8F411CAB B6AB7AF8541CF85755B8EA27239F08D2
             166646E4",
        );

        assert_eq!(BelT::apply_cbc(&y, &key(K2), block(S2), false), x);
    }

    #[test]
    fn cbc_round_trip_keeps_length() {
        let k = key(K1);
        let message: Vec<u8> = (0..80u8).collect();

        for length in BLOCK_SIZE..=message.len() {
            let plain = message[..length].to_vec();
            let encrypted = BelT::encrypt_cbc(plain.clone(), &k);

            assert_eq!(
                encrypted.len(),
                BLOCK_SIZE + length,
                "{length} bytes: ciphertext is the sync value plus the plaintext"
            );
            assert_eq!(
                BelT::decrypt_cbc(encrypted, &k),
                plain,
                "{length} bytes: round trip"
            );
        }
    }

    #[test]
    fn cbc_hides_repeated_blocks() {
        let k = key(K1);
        let plain = vec![0u8; 4 * BLOCK_SIZE];

        let encrypted = BelT::encrypt_cbc(plain.clone(), &k);
        let blocks: Vec<&[u8]> = encrypted.chunks(BLOCK_SIZE).collect();

        assert!(
            blocks[1] != blocks[2] && blocks[2] != blocks[3] && blocks[3] != blocks[4],
            "chaining must turn equal plaintext blocks into different ciphertext blocks"
        );
        assert_ne!(
            encrypted,
            BelT::encrypt_cbc(plain, &k),
            "a fresh sync value must give a different ciphertext"
        );
    }

    #[test]
    fn cbc_error_propagation_spans_two_blocks() {
        let k = key(K1);
        let plain = vec![0u8; 4 * BLOCK_SIZE];

        let mut encrypted = BelT::encrypt_cbc(plain.clone(), &k);
        encrypted[2 * BLOCK_SIZE] ^= 0x01;
        let decrypted = BelT::decrypt_cbc(encrypted, &k);

        let damaged: Vec<usize> = (0..plain.len())
            .filter(|&idx| decrypted[idx] != plain[idx])
            .collect();

        assert!(damaged.iter().all(|&idx| idx >= BLOCK_SIZE));
        assert!(damaged.iter().any(|&idx| idx < 2 * BLOCK_SIZE));
        assert_eq!(
            damaged.iter().filter(|&&idx| idx >= 2 * BLOCK_SIZE).count(),
            1,
            "in the next block only the flipped bit is damaged"
        );
        assert!(damaged.iter().all(|&idx| idx < 3 * BLOCK_SIZE));
    }

    #[test]
    fn mac_partial_block() {
        let x = bytes("B194BAC80A08F53B366D008E58");

        assert_eq!(
            BelT::compute_mac(x, &key(K1), MAX_MAC_BITS),
            Some(0x7260DA60138F96C9)
        );
    }

    #[test]
    fn mac_whole_blocks() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D61217B96181FE6786AD716B890B",
        );

        assert_eq!(
            BelT::compute_mac(x, &key(K1), MAX_MAC_BITS),
            Some(0x2DAB59771B4B16D0)
        );
    }

    #[test]
    fn mac_truncation_takes_leading_bits() {
        let x = bytes("B194BAC80A08F53B366D008E58");

        assert_eq!(BelT::compute_mac(x.clone(), &key(K1), 32), Some(0x7260DA60));
        assert_eq!(BelT::compute_mac(x, &key(K1), 16), Some(0x7260));
    }

    #[test]
    fn mac_of_the_empty_message_is_defined() {
        assert!(BelT::compute_mac(vec![], &key(K1), MAX_MAC_BITS).is_some());
    }

    #[test]
    fn mac_sees_the_length_of_the_message() {
        let x = bytes("B194BAC80A08F53B366D008E58");
        let mut padded = x.clone();
        padded.push(0);

        assert_ne!(
            BelT::compute_mac(x, &key(K1), MAX_MAC_BITS),
            BelT::compute_mac(padded, &key(K1), MAX_MAC_BITS),
            "the 0x80 padding bit must keep a zero byte from being invisible"
        );
    }

    #[test]
    fn mac_accepts_every_length() {
        let k = key(K1);
        let message: Vec<u8> = (0..80u8).collect();

        for length in 0..=message.len() {
            assert!(
                BelT::compute_mac(message[..length].to_vec(), &k, MAX_MAC_BITS).is_some(),
                "{length} bytes"
            );
        }
    }

    #[test]
    fn ctr_matches_a16() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D61217B96181FE6786AD716B890B",
        );
        let y = bytes(
            "52C9AF96FF50F64435FC43DEF56BD797 D5B5B1FF79FB41257AB9CDF6E63E81F8
             F00341473EAE409833622DE05213773A",
        );

        assert_eq!(BelT::apply_ctr(&x, &key(K1), block(S1)), y);
        assert_eq!(BelT::apply_ctr(&y, &key(K1), block(S1)), x);
    }

    #[test]
    fn cfm_encrypt_matches_a14() {
        let x = bytes(
            "B194BAC80A08F53B366D008E584A5DE4 8504FA9D1BB6C7AC252E72C202FDCE0D
             5BE3D61217B96181FE6786AD716B890B",
        );
        let y = bytes(
            "C31E490A90EFA374626CC99E4B7B8540 A6E48685464A5A06849C9CA769A1B0AE
             55C2CC5939303EC832DD2FE16C8E5A1B",
        );

        assert_eq!(BelT::apply_cfm(&x, &key(K1), block(S1), true), y);
    }

    #[test]
    fn cfm_decrypt_matches_a15() {
        let y = bytes(
            "E12BDC1AE28257EC703FCCF095EE8DF1 C1AB76389FE678CAF7C6F860D5BB9C4F
             F33C657B637C306ADD4EA7799EB23D31",
        );
        let x = bytes(
            "FA9D107A86F375EE65CD1DB881224BD0 16AFF814938ED39B3361ABB0BF0851B6
             52244EB06842DD4C94AA4500774E40BB",
        );

        assert_eq!(BelT::apply_cfm(&y, &key(K2), block(S2), false), x);
    }

    #[test]
    fn ctr_and_cfm_round_trip_keeps_length() {
        let k = key(K1);
        let message: Vec<u8> = (0..80u8).collect();

        for length in 0..=message.len() {
            let plain = message[..length].to_vec();

            let ctr = BelT::encrypt_ctr(plain.clone(), &k);
            assert_eq!(ctr.len(), BLOCK_SIZE + length, "CTR, {length} bytes");
            assert_eq!(BelT::decrypt_ctr(ctr, &k), plain, "CTR, {length} bytes");

            let cfm = BelT::encrypt_cfm(plain.clone(), &k);
            assert_eq!(cfm.len(), BLOCK_SIZE + length, "CFM, {length} bytes");
            assert_eq!(BelT::decrypt_cfm(cfm, &k), plain, "CFM, {length} bytes");
        }
    }

    #[test]
    fn ctr_gamma_depends_on_the_sync_value() {
        let k = key(K1);
        let plain = vec![0u8; 4 * BLOCK_SIZE];

        let first = BelT::encrypt_ctr(plain.clone(), &k);
        let second = BelT::encrypt_ctr(plain, &k);

        assert_ne!(first[..BLOCK_SIZE], second[..BLOCK_SIZE]);
        assert_ne!(first[BLOCK_SIZE..], second[BLOCK_SIZE..]);
    }

    #[test]
    fn ctr_damage_stays_in_one_byte() {
        let k = key(K1);
        let plain = vec![0u8; 4 * BLOCK_SIZE];

        let mut encrypted = BelT::encrypt_ctr(plain.clone(), &k);
        encrypted[2 * BLOCK_SIZE] ^= 0x01;
        let decrypted = BelT::decrypt_ctr(encrypted, &k);

        let damaged: Vec<usize> = (0..plain.len())
            .filter(|&idx| decrypted[idx] != plain[idx])
            .collect();

        assert_eq!(damaged, vec![BLOCK_SIZE]);
    }

    #[test]
    fn cfm_damage_spans_the_next_block() {
        let k = key(K1);
        let plain = vec![0u8; 4 * BLOCK_SIZE];

        let mut encrypted = BelT::encrypt_cfm(plain.clone(), &k);
        encrypted[2 * BLOCK_SIZE] ^= 0x01;
        let decrypted = BelT::decrypt_cfm(encrypted, &k);

        let damaged: Vec<usize> = (0..plain.len())
            .filter(|&idx| decrypted[idx] != plain[idx])
            .collect();

        assert_eq!(damaged.first(), Some(&BLOCK_SIZE));
        assert!(damaged.iter().filter(|&&idx| idx < 2 * BLOCK_SIZE).count() == 1);
        assert!(damaged.iter().filter(|&&idx| idx >= 2 * BLOCK_SIZE).count() > 1);
        assert!(damaged.iter().all(|&idx| idx < 3 * BLOCK_SIZE));
    }
}
