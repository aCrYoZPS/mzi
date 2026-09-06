mod encryption;
use encryption::gost28147_89::*;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

const KEY: Gost28147_89Key = Gost28147_89Key([1, 2, 3, 4, 5, 6, 7, 8]);
const DEFAULT_MAC_BITS: usize = 32;
const ENCRYPTED_EXTENSION: &str = "gost";
type CipherFn = fn(Vec<u8>, &Gost28147_89Key) -> Vec<u8>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum IoMode {
    Text,
    File,
}

impl IoMode {
    fn name(&self) -> &'static str {
        match self {
            IoMode::Text => "text",
            IoMode::File => "file",
        }
    }
}

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

fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return Err("hex input must contain an even number of digits".to_string());
    }
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("hex input contains a non-hex character".to_string());
    }

    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for i in (0..digits.len()).step_by(2) {
        let byte = u8::from_str_radix(&digits[i..i + 2], 16).expect("checked to be valid hex");
        bytes.push(byte);
    }

    return Ok(bytes);
}

fn cipher_fns(encryption_type: Gost28147_89Type) -> (CipherFn, CipherFn) {
    return match encryption_type {
        Gost28147_89Type::ECB => (Gost28147_89::encrypt_ecb, Gost28147_89::decrypt_ecb),
        Gost28147_89Type::CTR => (Gost28147_89::encrypt_ctr, Gost28147_89::decrypt_ctr),
        Gost28147_89Type::CFM => (Gost28147_89::encrypt_cfm, Gost28147_89::decrypt_cfm),
    };
}

fn check_ciphertext(bytes: &[u8], encryption_type: Gost28147_89Type) -> Result<(), String> {
    match encryption_type {
        Gost28147_89Type::ECB => {
            if bytes.is_empty() || (bytes.len() - 1) % 8 != 0 {
                return Err(format!(
                    "ECB ciphertext must be a whole number of 8-byte blocks plus one padding byte, got {} bytes",
                    bytes.len()
                ));
            }
            let padding = bytes[bytes.len() - 1] as usize;
            if padding > 7 || (padding > 0 && bytes.len() == 1) {
                return Err(format!("invalid padding byte {padding} in ECB ciphertext"));
            }
        }
        Gost28147_89Type::CTR | Gost28147_89Type::CFM => {
            if bytes.len() < 8 {
                return Err(format!(
                    "{encryption_type} ciphertext must start with an 8-byte sync value, got {} bytes",
                    bytes.len()
                ));
            }
        }
    }

    return Ok(());
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    return fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()));
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    return fs::write(path, bytes).map_err(|err| format!("cannot write {}: {err}", path.display()));
}

fn default_output_path(source: &Path, encrypt: bool) -> PathBuf {
    if encrypt {
        let mut name = source.as_os_str().to_os_string();
        name.push(format!(".{ENCRYPTED_EXTENSION}"));

        return PathBuf::from(name);
    }

    if source
        .extension()
        .is_some_and(|ext| ext == ENCRYPTED_EXTENSION)
    {
        return source.with_extension("");
    }

    let mut name = source.as_os_str().to_os_string();
    name.push(".decrypted");

    return PathBuf::from(name);
}

fn ask_input_path(label: &str) -> Result<PathBuf, String> {
    let path = prompt(label);
    if path.is_empty() {
        return Err("no input file given".to_string());
    }

    return Ok(PathBuf::from(path));
}

fn ask_output_path(default: &Path) -> Result<PathBuf, String> {
    let answer = prompt(&format!("Output file [{}]: ", default.display()));
    let path = if answer.is_empty() {
        default.to_path_buf()
    } else {
        PathBuf::from(answer)
    };

    if path.exists() {
        let confirmation = prompt(&format!(
            "{} already exists, overwrite? [y/N]: ",
            path.display()
        ));
        if !confirmation.eq_ignore_ascii_case("y") {
            return Err("cancelled, the output file was left untouched".to_string());
        }
    }

    return Ok(path);
}

fn read_payload(io_mode: IoMode, encrypt: bool) -> Result<(Vec<u8>, Option<PathBuf>), String> {
    match io_mode {
        IoMode::Text => {
            let bytes = if encrypt {
                prompt("Plaintext: ").into_bytes()
            } else {
                from_hex(&prompt("Ciphertext (hex): "))?
            };

            return Ok((bytes, None));
        }
        IoMode::File => {
            let path = ask_input_path(if encrypt {
                "Plaintext file: "
            } else {
                "Ciphertext file: "
            })?;
            let bytes = read_file(&path)?;

            return Ok((bytes, Some(path)));
        }
    }
}

fn run_cipher(
    io_mode: IoMode,
    encrypt: bool,
    encryption_type: Gost28147_89Type,
    key: &Gost28147_89Key,
) -> Result<(), String> {
    let (encrypt_fn, decrypt_fn) = cipher_fns(encryption_type);
    let cipher_fn = if encrypt { encrypt_fn } else { decrypt_fn };

    let (input, source) = read_payload(io_mode, encrypt)?;
    if input.is_empty() {
        return Err("nothing to process: the input is empty".to_string());
    }
    if !encrypt {
        check_ciphertext(&input, encryption_type)?;
    }

    let destination = match &source {
        Some(path) => Some(ask_output_path(&default_output_path(path, encrypt))?),
        None => None,
    };

    let output = cipher_fn(input.clone(), key);

    println!(
        "  mode      : {encryption_type} ({})",
        if encrypt { "encryption" } else { "decryption" }
    );

    match source {
        Some(path) => {
            let destination = destination.expect("a file source always has a destination");
            write_file(&destination, &output)?;

            println!("  input     : {} ({} bytes)", path.display(), input.len());
            println!(
                "  output    : {} ({} bytes)",
                destination.display(),
                output.len()
            );
        }
        None => {
            if encrypt {
                println!("  plaintext : {} bytes", input.len());
                println!("  encrypted : {} ({} bytes)", to_hex(&output), output.len());
            } else {
                println!("  encrypted : {} bytes", input.len());
                match String::from_utf8(output.clone()) {
                    Ok(text) => println!("  decrypted : {text} ({} bytes)", output.len()),
                    Err(_) => println!(
                        "  decrypted : <not valid UTF-8> {} ({} bytes)",
                        to_hex(&output),
                        output.len()
                    ),
                }
            }
        }
    }

    return Ok(());
}

fn run_mac(io_mode: IoMode, key: &Gost28147_89Key) -> Result<(), String> {
    let (message, source) = read_payload(io_mode, true)?;

    let bits_input = prompt(&format!("MAC length in bits [{DEFAULT_MAC_BITS}]: "));
    let mac_bits = if bits_input.is_empty() {
        DEFAULT_MAC_BITS
    } else {
        match bits_input.parse::<usize>() {
            Ok(bits) if (1..=MAX_MAC_BITS).contains(&bits) => bits,
            _ => {
                return Err(format!(
                    "MAC length must be an integer in 1..={MAX_MAC_BITS}"
                ));
            }
        }
    };

    let mac = Gost28147_89::compute_mac(message.clone(), key, mac_bits)
        .ok_or_else(|| "an empty message has no MAC".to_string())?;

    match source {
        Some(path) => println!("  message : {} ({} bytes)", path.display(), message.len()),
        None => println!("  message : {} bytes", message.len()),
    }
    println!("  mac     : {mac:08X} ({mac_bits} bits)");

    return Ok(());
}

fn parse_key(hex_key: &str) -> Result<Gost28147_89Key, String> {
    if hex_key.len() != 64 {
        return Err("valid key should be 256 bits (64 characters)".to_string());
    }

    let bytes = from_hex(hex_key)?;
    let mut new_key = [0u32; 8];
    for (idx, word) in bytes.chunks(4).enumerate() {
        new_key[idx] = u32::from_be_bytes(word.try_into().expect("64 hex digits give 8 words"));
    }

    return Ok(Gost28147_89Key(new_key));
}

fn main() {
    let mut key = KEY;
    let mut io_mode = IoMode::Text;

    loop {
        println!();
        println!("Input/output: {}", io_mode.name());
        println!("1) encrypt (ECB)      4) decrypt (ECB)");
        println!("2) encrypt (CTR)      5) decrypt (CTR)");
        println!("3) encrypt (CFM)      6) decrypt (CFM)");
        println!("7) MAC");

        let choice = prompt(
            "Choice (or 'm' to switch text/file mode, 'k' to see key, 'c' to change key, 'q' to quit): ",
        );
        println!();

        let result = match choice.as_str() {
            "1" => run_cipher(io_mode, true, Gost28147_89Type::ECB, &key),
            "2" => run_cipher(io_mode, true, Gost28147_89Type::CTR, &key),
            "3" => run_cipher(io_mode, true, Gost28147_89Type::CFM, &key),
            "4" => run_cipher(io_mode, false, Gost28147_89Type::ECB, &key),
            "5" => run_cipher(io_mode, false, Gost28147_89Type::CTR, &key),
            "6" => run_cipher(io_mode, false, Gost28147_89Type::CFM, &key),
            "7" => run_mac(io_mode, &key),
            "m" => {
                io_mode = match io_mode {
                    IoMode::Text => IoMode::File,
                    IoMode::File => IoMode::Text,
                };
                println!("Switched to {} mode", io_mode.name());
                Ok(())
            }
            "k" => {
                println!("Key is: {key}");
                Ok(())
            }
            "c" => match parse_key(prompt("Key: ").as_str()) {
                Ok(new_key) => {
                    key = new_key;
                    Ok(())
                }
                Err(err) => Err(err),
            },
            "q" => break,
            _ => Err(format!("unknown choice: {choice:?}")),
        };

        if let Err(err) = result {
            println!("Error: {err}");
        }
    }
}
