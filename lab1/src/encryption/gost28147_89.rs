const BLOCK_SIZE: usize = 8;
const ITERATIONS: usize = 32;

pub struct Gost28147_89 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gost28147_89Key(pub [u32; 8]);

impl Gost28147_89Key {
    pub fn new(subkeys: [u32; 8]) -> Self {
        Self(subkeys)
    }
}

impl Gost28147_89 {
    fn f(half: u32, subkey: u32) -> u32 {
        let sum = (half + subkey) % 2u32.pow(32);
    }
    pub fn encrypt(mut plain_bytes: Vec<u8>, key: Gost28147_89Key) -> Vec<u8> {
        let total_bytes = plain_bytes.len();
        let blocks = plain_bytes.chunks_mut(BLOCK_SIZE);
        let result: Vec<u8> = vec![];

        for block in blocks {
            let a_bytes = block[0..(BLOCK_SIZE / 2)]
                .try_into()
                .expect("u32 can only be constructed from [u8;4]");
            let b_bytes = block[(BLOCK_SIZE / 2 + 1)..]
                .try_into()
                .expect("u32 can only be constructed from [u8;4]");
            let mut a = u32::from_ne_bytes(a_bytes);
            let mut b = u32::from_ne_bytes(b_bytes);

            for iteration in 0..ITERATIONS {
                let a_cpy = a;
                a = b ^ a;
                b = a_cpy;
            }
        }
        todo!("Impl")
    }
    pub fn decrypt(encrypted_bytes: Vec<u8>, key: Gost28147_89Key) -> Vec<u8> {
        todo!("Impl")
    }
}
