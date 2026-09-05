mod encryption;
use encryption::gost28147_89::*;
use std::io::{self, Write};

const KEY: Gost28147_89Key = Gost28147_89Key([1, 2, 3, 4, 5, 6, 7, 8]);
const DEFAULT_MAC_BITS: usize = 32;
type CipherFn = fn(Vec<u8>, &Gost28147_89Key) -> Vec<u8>;

fn prompt(label: &str) -> String {
    print!("{label}");
    io::stdout().flush().expect("failed to flush stdout");

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .expect("failed to read stdin");

    return line.trim_end_matches(['\r', '\n']).to_string();
}

fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02X}"));
    }

    return hex;
}

fn run_gost28147_89(plaintext: &str, key: &Gost28147_89Key, encryption_type: Gost28147_89Type) {
    let (encryption_fn, decryption_fn): (CipherFn, CipherFn) = match encryption_type {
        Gost28147_89Type::ECB => (Gost28147_89::encrypt_ecb, Gost28147_89::decrypt_ecb),
        Gost28147_89Type::CTR => (Gost28147_89::encrypt_ctr, Gost28147_89::decrypt_ctr),
        Gost28147_89Type::CFM => (Gost28147_89::encrypt_cfm, Gost28147_89::decrypt_cfm),
    };

    let encrypted = encryption_fn(plaintext.as_bytes().to_vec(), key);
    let decrypted = decryption_fn(encrypted.clone(), key);

    println!("  plaintext : {plaintext} ({} bytes)", plaintext.len());
    println!(
        "  encrypted : {} ({} bytes)",
        to_hex(&encrypted),
        encrypted.len()
    );
    match String::from_utf8(decrypted) {
        Ok(text) => println!("  decrypted : {text} ({} bytes)", text.len()),
        Err(err) => println!("  decrypted : <not valid UTF-8> {err}"),
    }
}

fn run_mac(plaintext: &str, key: &Gost28147_89Key) {
    let bits_input = prompt(&format!("MAC length in bits [{DEFAULT_MAC_BITS}]: "));
    let mac_bits = if bits_input.is_empty() {
        DEFAULT_MAC_BITS
    } else {
        match bits_input.parse::<usize>() {
            Ok(bits) if (1..=MAX_MAC_BITS).contains(&bits) => bits,
            _ => {
                println!("MAC length must be an integer in 1..={MAX_MAC_BITS}");
                return;
            }
        }
    };

    match Gost28147_89::compute_mac(plaintext.as_bytes().to_vec(), key, mac_bits) {
        Some(mac) => {
            println!("  message : {plaintext} ({} bytes)", plaintext.len());
            println!("  mac     : {mac:08X} ({mac_bits} bits)");
        }
        None => println!("  an empty message has no MAC"),
    }
}

fn parse_key(hex_key: &str) -> Option<Gost28147_89Key> {
    if hex_key.len() != 64 {
        println!("valid key should be 256 bits (64 characters)");
        return None;
    }
    if !hex_key.chars().all(|c| c.is_ascii_hexdigit()) {
        println!("invalid hex");
        return None;
    }

    let mut new_key = [0u32; 8];

    for i in (0..64).step_by(8) {
        if let Ok(subkey) = u32::from_str_radix(&hex_key[i..i + 8], 16) {
            new_key[i / 8] = subkey;
        } else {
            unreachable!()
        }
    }

    Some(Gost28147_89Key(new_key))
}

fn main() {
    let mut plaintext = prompt("Plaintext: ");
    let mut key = KEY;

    loop {
        println!();
        println!("1) GOST 28147-89 (ECB)");
        println!("2) GOST 28147-89 (CTR)");
        println!("3) GOST 28147-89 (CFM)");
        println!("4) GOST 28147-89 (MAC)");

        let choice = prompt(
            "Choice (or 'p' to change the plaintext, 'q' to quit, 'k' to see key, 'c' to change key): ",
        );
        println!();

        match choice.as_str() {
            "1" => run_gost28147_89(&plaintext, &key, Gost28147_89Type::ECB),
            "2" => run_gost28147_89(&plaintext, &key, Gost28147_89Type::CTR),
            "3" => run_gost28147_89(&plaintext, &key, Gost28147_89Type::CFM),
            "4" => run_mac(&plaintext, &key),
            "p" => plaintext = prompt("Plaintext: "),
            "q" => break,
            "c" => key = parse_key(prompt("Key: ").as_str()).unwrap_or(key),
            "k" => println!("Key is: {}", key),
            _ => println!("Unknown choice: {choice:?}"),
        }
    }
}
