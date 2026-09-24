const BLOCK_SIZE: usize = 64;
const ITERATIONS: usize = 80;

#[derive(Clone)]
struct Sha1Buffer {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

pub struct Sha1 {}

impl Sha1 {
    pub fn hash(plain_bytes: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(plain_bytes);

        let original_len = bytes.len() as u64 * 8;
        bytes.push(0x80);

        let padding = (56 + 64 - bytes.len() % 64) % 64;
        bytes.resize(bytes.len() + padding, 0u8);
        bytes.extend_from_slice(&original_len.to_be_bytes());

        let mut buffer = Sha1Buffer {
            a: 0x67452301,
            b: 0xEFCDAB89,
            c: 0x98BADCFE,
            d: 0x10325476,
            e: 0xC3D2E1F0,
        };

        for block in bytes.chunks(BLOCK_SIZE) {
            let old_buffer = buffer.clone();

            let mut w: Vec<u32> = block
                .chunks(4)
                .map(|chunk| {
                    u32::from_be_bytes(chunk.try_into().expect("u32 should be built from [u8; 4]"))
                })
                .collect();

            w.resize(ITERATIONS, 0);

            for i in 16..ITERATIONS {
                w[i] = (w[i - 16] ^ w[i - 14] ^ w[i - 8] ^ w[i - 3]).rotate_left(1);
            }

            let mut k: u32;
            let mut f_t: fn(u32, u32, u32) -> u32;
            for i in 0..ITERATIONS {
                match i {
                    0..20 => {
                        f_t = |b, c, d| (b & c) | (!b & d);
                        k = 0x5A827999;
                    }
                    20..40 => {
                        f_t = |b, c, d| b ^ c ^ d;
                        k = 0x6ED9EBA1;
                    }
                    40..60 => {
                        f_t = |b, c, d| (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDC;
                    }
                    60..80 => {
                        f_t = |b, c, d| b ^ c ^ d;
                        k = 0xCA62C1D6;
                    }
                    _ => unreachable!(),
                }

                let t = buffer
                    .a
                    .rotate_left(5)
                    .wrapping_add(f_t(buffer.b, buffer.c, buffer.d))
                    .wrapping_add(buffer.e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);

                buffer.e = buffer.d;
                buffer.d = buffer.c;
                buffer.c = buffer.b.rotate_left(30);
                buffer.b = buffer.a;
                buffer.a = t;
            }

            buffer.a = buffer.a.wrapping_add(old_buffer.a);
            buffer.b = buffer.b.wrapping_add(old_buffer.b);
            buffer.c = buffer.c.wrapping_add(old_buffer.c);
            buffer.d = buffer.d.wrapping_add(old_buffer.d);
            buffer.e = buffer.e.wrapping_add(old_buffer.e);
        }

        let mut result: Vec<u8> = vec![];
        result.extend_from_slice(&buffer.a.to_be_bytes());
        result.extend_from_slice(&buffer.b.to_be_bytes());
        result.extend_from_slice(&buffer.c.to_be_bytes());
        result.extend_from_slice(&buffer.d.to_be_bytes());
        result.extend_from_slice(&buffer.e.to_be_bytes());

        return result;
    }
}
