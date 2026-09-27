#[allow(dead_code)]
mod encryption;
use common::cli::{self, IoMode};
use encryption::bit_vecs::DenseBitVec;
use encryption::qc_mdpc::*;
use rand::rngs::OsRng;
use rand::{Rng, SeedableRng, rngs::StdRng};
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

fn trace_block(private: &PrivateKey, public: &PublicKey) -> Result<(), String> {
    let r = public.r();
    let k = r / 8;
    let mut rng = StdRng::from_rng(&mut OsRng).unwrap();

    let answer = cli::prompt(&format!("Message (up to {k} bytes, empty for random): "));
    let block = if answer.is_empty() {
        (0..k).map(|_| rng.gen_range(0..=u8::MAX)).collect()
    } else {
        answer.into_bytes()
    };
    if block.len() > k {
        return Err(format!("expected at most {k} bytes, got {}", block.len()));
    }
    println!();

    let m = DenseBitVec::from_bytes(r, &block);
    let (c0, c1) = QcMdpc::encrypt_block(&block, public, &mut rng);
    let mut e0 = c0.xor(&m.mul(public.a()));
    let mut e1 = c1.xor(&m.mul(public.b()));

    println!("Encryption");
    print_dense("m", &m);
    print_list("supp(e0)", &e0.support());
    print_list("supp(e1)", &e1.support());
    println!("  |e0| + |e1|   : {}", e0.weight() + e1.weight());
    print_dense("c0 = m·A + e0", &c0);
    print_dense("c1 = m·B + e1", &c1);

    let mut s = private.h0().mul(&c0).xor(&private.h1().mul(&c1));
    println!("Decryption");
    print_dense("syndrome s", &s);

    let start = Instant::now();
    let Some((found0, found1)) = QcMdpc::decode(&mut s, private) else {
        println!("  decoder       : FAILURE after {:.2?}", start.elapsed());
        return Ok(());
    };
    println!("  decoder       : done in {:.2?}", start.elapsed());

    e0.xor_assign(&found0);
    e1.xor_assign(&found1);
    println!(
        "  errors found  : {}",
        if e0.is_zero() && e1.is_zero() {
            "all of them, exactly"
        } else {
            "MISMATCH"
        }
    );

    let mut masked = c0.clone();
    masked.xor_assign(&found0);
    let decrypted = masked.mul(private.a_inv());
    print_dense("decrypted m", &decrypted);
    println!(
        "  result        : {}",
        if decrypted == m {
            "matches the message"
        } else {
            "MISMATCH"
        }
    );
    println!("  block sizes   : {r} bits in, {} bits out", 2 * r);

    // проверка разреженного ключа: h0 должен восстанавливаться из открытого q
    let q = private.a_inv().mul(public.b());
    let h0_ok = private.h1().mul(&q) == DenseBitVec::from(private.h0());
    println!("  h1·q = h0     : {}", if h0_ok { "yes" } else { "NO" });

    return Ok(());
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
        println!("3) trace one block");

        let choice = cli::prompt(
            "Choice (or 'm' to switch text/file mode, 'k' to see keys, 'g' to generate keys, 'q' to quit): ",
        );
        println!();

        let result = match choice.as_str() {
            "1" => run_cipher(io_mode, true, &private, &public),
            "2" => run_cipher(io_mode, false, &private, &public),
            "3" => trace_block(&private, &public),
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
