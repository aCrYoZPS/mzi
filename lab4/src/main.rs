#[allow(dead_code)]
mod encryption;
use common::cli::{self, IoMode};
use encryption::bit_vecs::DenseBitVec;
use encryption::qc_mdpc::*;
use std::time::Instant;

const TITLE: &str = "McEliece cryptosystem (QC-MDPC)";
const ENCRYPTED_EXTENSION: &str = "mce";
const PRINT_LIMIT: usize = 64;
const HEX_LIMIT: usize = 32;

fn generate_keys() -> (PrivateKey, PublicKey) {
    println!(
        "Generating keys for r = {}, d = {}, t = {}...",
        CRYPTO_PARAMS.r(),
        CRYPTO_PARAMS.d(),
        CRYPTO_PARAMS.t()
    );
    let start = Instant::now();
    let keys = QcMdpc::keygen(CRYPTO_PARAMS);
    println!("Done in {:.2?}", start.elapsed());

    return keys;
}

fn print_list<T: ToString>(label: &str, items: &[T]) {
    let shown: Vec<String> = items
        .iter()
        .take(PRINT_LIMIT)
        .map(|item| item.to_string())
        .collect();
    let rest = items.len() - shown.len();
    let tail = if rest > 0 {
        format!(", … ({rest} more)")
    } else {
        String::new()
    };

    println!("  {label:<14}: {}{tail}", shown.join(", "));
}

fn print_dense(label: &str, v: &DenseBitVec) {
    let bytes = v.to_bytes();
    let shown = cli::to_hex(&bytes[..bytes.len().min(HEX_LIMIT)]);
    let tail = if bytes.len() > HEX_LIMIT { "…" } else { "" };

    println!(
        "  {label:<14}: {shown}{tail} (weight {}, {} bytes)",
        v.weight(),
        bytes.len()
    );
}

fn print_keys(private: &PrivateKey, public: &PublicKey) {
    let half = public.r().div_ceil(8);

    println!("Public key ({} bytes)", 2 * half);
    println!("  r, t          : {}, {}", public.r(), public.t());
    print_dense("A = a", public.a());
    print_dense("B = a·q", public.b());

    println!("Private key");
    print_list("supp(h0)", private.h0().positions());
    print_list("supp(h1)", private.h1().positions());
    print_dense("a⁻¹", private.a_inv());
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

    let start = Instant::now();
    let output = if encrypt {
        QcMdpc::encrypt(&input, public)
    } else {
        QcMdpc::decrypt(&input, private).ok_or(
            "a block failed to decrypt: decoding failure, wrong key or damaged ciphertext",
        )?
    };

    println!(
        "  mode      : {}",
        if encrypt { "encryption" } else { "decryption" }
    );
    println!("  time      : {:.2?}", start.elapsed());

    return cli::emit_output(
        encrypt,
        &input,
        &output,
        source.as_deref(),
        destination.as_deref(),
    );
}

fn main() {
    cli::init(env!("CARGO_MANIFEST_DIR"));
    let (mut private, mut public) = generate_keys();
    let mut io_mode = IoMode::Text;

    loop {
        println!();
        println!(
            "{TITLE} — input/output: {}, r = {}, t = {}",
            io_mode.name(),
            public.r(),
            public.t()
        );
        println!("{:<22}2) decrypt", "1) encrypt");

        let choice = cli::prompt(
            "Choice (or 'm' to switch text/file mode, 'k' to see keys, 'g' to generate keys, 'q' to quit): ",
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
            "q" => break,
            _ => Err(format!("unknown choice: {choice:?}")),
        };

        if let Err(err) = result {
            println!("Error: {err}");
        }
    }
}
