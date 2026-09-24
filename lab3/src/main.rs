mod encryption;
use common::cli::{self, IoMode};
use encryption::rabin::*;
use num_bigint::BigUint;
use num_prime::nt_funcs::is_prime;

const TITLE: &str = "Rabin cryptosystem";
const ENCRYPTED_EXTENSION: &str = "rabin";
const MIN_MODULUS_BYTES: usize = 2 * REDUNDANCY_SIZE + 2;

fn generate_keys() -> (PrivateKey, PublicKey) {
    println!("Generating keys...");

    return Rabin::keygen();
}

fn parse_prime(label: &str) -> Result<BigUint, String> {
    let digits: String = cli::prompt(label)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let prime = BigUint::parse_bytes(digits.as_bytes(), 16)
        .ok_or_else(|| format!("{label:?} expects a hex number"))?;

    if &prime % 4u32 != BigUint::from(3u32) {
        return Err(format!("{prime:X} is not 3 mod 4"));
    }
    if !is_prime(&prime, None).probably() {
        return Err(format!("{prime:X} is not prime"));
    }

    return Ok(prime);
}

fn read_keys() -> Result<(PrivateKey, PublicKey), String> {
    let p = parse_prime("p (hex): ")?;
    let q = parse_prime("q (hex): ")?;
    if p == q {
        return Err("p and q must differ".to_string());
    }

    let n = &p * &q;
    if (n.bits().div_ceil(8) as usize) < MIN_MODULUS_BYTES {
        return Err(format!(
            "n = p·q must be at least {MIN_MODULUS_BYTES} bytes long"
        ));
    }

    return Ok((PrivateKey::new(p, q), PublicKey::new(n)));
}

fn print_keys(private: &PrivateKey, public: &PublicKey) {
    println!("  n : {:X} ({} bits)", public.n(), public.n().bits());
    println!("  p : {:X} ({} bits)", private.p(), private.p().bits());
    println!("  q : {:X} ({} bits)", private.q(), private.q().bits());
}

fn run_cipher(
    io_mode: IoMode,
    encrypt: bool,
    private: &PrivateKey,
    public: &PublicKey,
) -> Result<(), String> {
    let (input, source) = cli::read_payload(io_mode, encrypt)?;
    if input.is_empty() {
        return Err("nothing to process: the input is empty".to_string());
    }

    let destination = match &source {
        Some(path) => Some(cli::ask_output_path(&cli::default_output_path(
            path,
            ENCRYPTED_EXTENSION,
            encrypt,
        ))?),
        None => None,
    };

    let output = if encrypt {
        Rabin::encrypt(input.clone(), public)
    } else {
        Rabin::decrypt(input.clone(), private)?
    };

    println!(
        "  mode      : {}",
        if encrypt { "encryption" } else { "decryption" }
    );

    return cli::emit_output(
        encrypt,
        &input,
        &output,
        source.as_deref(),
        destination.as_deref(),
    );
}

fn main() {
    let (mut private, mut public) = generate_keys();
    let mut io_mode = IoMode::Text;

    loop {
        println!();
        println!("{TITLE} — input/output: {}", io_mode.name());
        println!("{:<22}2) decrypt", "1) encrypt");

        let choice = cli::prompt(
            "Choice (or 'm' to switch text/file mode, 'k' to see keys, 'g' to generate keys, 'c' to change keys, 'q' to quit): ",
        );
        println!();

        let result = match choice.as_str() {
            "1" => run_cipher(io_mode, true, &private, &public),
            "2" => run_cipher(io_mode, false, &private, &public),
            "m" => {
                io_mode = io_mode.toggled();
                println!("Switched to {} mode", io_mode.name());
                Ok(())
            }
            "k" => {
                print_keys(&private, &public);
                Ok(())
            }
            "g" => {
                (private, public) = generate_keys();
                Ok(())
            }
            "c" => read_keys().map(|keys| (private, public) = keys),
            "q" => break,
            _ => Err(format!("unknown choice: {choice:?}")),
        };

        if let Err(err) = result {
            println!("Error: {err}");
        }
    }
}
