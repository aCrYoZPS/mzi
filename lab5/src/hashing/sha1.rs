use std::vec;

const BLOCK_SIZE: usize = 64;
const ITERATIONS: usize = 80;

struct Sha1Buffer {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

pub struct Sha1 {}

impl Sha1 {
    fn sha(idx: usize, block: &[u8], buffer: &mut Sha1Buffer) {}

    pub fn hash(mut bytes: Vec<u8>) -> Vec<u8> {
        let original_len = bytes.len();
        let padding = {
            let pd = 56 - (bytes.len() % 64);
            if pd == 0 { 56 } else { pd }
        };

        bytes.push(0x80);
        bytes.resize(bytes.len() + padding - 1, 0u8);
        bytes.extend_from_slice(&original_len.to_le_bytes());

        let mut buffer = Sha1Buffer {
            a: 0x67452301,
            b: 0xEFCDAB89,
            c: 0x98BADCFE,
            d: 0x10325476,
            e: 0xC3D2E1F0,
        };

        todo!()
    }
}
