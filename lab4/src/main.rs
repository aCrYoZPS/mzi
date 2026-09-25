#[allow(dead_code)]
mod encryption;
use common::cli::{self, IoMode};
use encryption::gf::{MAX_M, MIN_M};
use encryption::matrix::{BitVec, Matrix};
use encryption::mceliece::*;
use rand::rngs::OsRng;
use rand::{SeedableRng, rngs::StdRng};
use std::time::Instant;

const TITLE: &str = "McEliece cryptosystem";
const ENCRYPTED_EXTENSION: &str = "mce";
const PRESETS: [(&str, Params); 3] = [
    ("toy", Params::TOY),
    ("small", Params::SMALL),
    ("original (1978)", Params::ORIGINAL),
];
const PRINT_LIMIT: usize = 64;

fn generate_keys(params: Params) -> Result<(PrivateKey, PublicKey), String> {
    println!(
        "Generating keys for m = {}, n = {}, t = {}...",
        params.m, params.n, params.t
    );
    let start = Instant::now();
    let keys = McEliece::keygen(params)?;
    println!("Done in {:.2?}", start.elapsed());

    return Ok(keys);
}

fn parse_number(label: &str, default: usize) -> Result<usize, String> {
    let answer = cli::prompt(&format!("{label} [{default}]: "));
    if answer.is_empty() {
        return Ok(default);
    }

    return answer
        .trim()
        .parse()
        .map_err(|_| format!("{label} expects a non-negative integer"));
}

fn read_params(current: Params) -> Result<Params, String> {
    for (idx, (name, p)) in PRESETS.iter().enumerate() {
        println!(
            "{}) {name:<16} m = {:<2}, n = {:<4}, t = {}",
            idx + 1,
            p.m,
            p.n,
            p.t
        );
    }
    println!("{}) custom", PRESETS.len() + 1);

    let choice = cli::prompt("Parameters [keep current]: ");
    if choice.is_empty() {
        return Ok(current);
    }
    match choice.parse::<usize>() {
        Ok(idx) if (1..=PRESETS.len()).contains(&idx) => return Ok(PRESETS[idx - 1].1),
        Ok(idx) if idx == PRESETS.len() + 1 => {}
        _ => return Err(format!("unknown choice: {choice:?}")),
    }

    let m = parse_number(&format!("m ({MIN_M}..={MAX_M})"), current.m as usize)?;
    let n = parse_number(
        &format!("n (up to 2^m = {})", 1usize << m.min(MAX_M as usize)),
        current.n,
    )?;
    let t = parse_number("t", current.t)?;

    return Ok(Params { m: m as u32, n, t });
}

fn field_polynomial(modulus: u32) -> String {
    let terms: Vec<String> = (0..u32::BITS)
        .rev()
        .filter(|i| modulus >> i & 1 == 1)
        .map(|i| match i {
            0 => "1".to_string(),
            1 => "z".to_string(),
            _ => format!("z^{i}"),
        })
        .collect();

    return terms.join(" + ");
}

fn grouped(v: &BitVec) -> String {
    let bits = v.to_bit_string();
    let groups: Vec<&str> = bits
        .as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();

    return groups.join(" ");
}

fn print_matrix(label: &str, matrix: &Matrix) {
    let (rows, cols) = (matrix.row_count(), matrix.col_count());
    println!(
        "  {label:<11}: {rows} × {cols}, {} bytes",
        (rows * cols).div_ceil(8)
    );
    if cols > PRINT_LIMIT || rows > PRINT_LIMIT {
        return;
    }

    for row in matrix.rows() {
        println!("  {:<11}  {}", "", grouped(row));
    }
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

    println!("  {label:<11}: {}{tail}", shown.join(", "));
}

fn print_keys(private: &PrivateKey, public: &PublicKey) {
    let code = private.code();
    let field = code.field();

    println!("Public key");
    println!(
        "  n, k, t    : {}, {}, {}",
        public.n(),
        public.k(),
        public.t()
    );
    print_matrix("G' = S·G·P", public.matrix());

    println!("Private key");
    println!(
        "  field      : GF(2^{}) = GF(2)[z]/({})",
        field.m(),
        field_polynomial(field.modulus())
    );
    println!("  g(x)       : {}", code.g().display(field));
    let support: Vec<String> = code.support().iter().map(|&a| field.display(a)).collect();
    print_list("support L", &support);
    print_matrix("S⁻¹", private.s_inv());
    print_list("P⁻¹", private.p_inv().as_slice());
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
        McEliece::encrypt(input.clone(), public)
    } else {
        McEliece::decrypt(input.clone(), private)?
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

fn trace_block(private: &PrivateKey, public: &PublicKey) -> Result<(), String> {
    let (n, k) = (public.n(), public.k());
    let mut rng = StdRng::from_rng(&mut OsRng).unwrap();

    let answer = cli::prompt(&format!("Message ({k} bits, empty for random): "));
    let message = if answer.trim().is_empty() {
        BitVec::random(k, &mut rng)
    } else {
        BitVec::from_bit_string(&answer)?
    };
    if message.len() != k {
        return Err(format!("expected {k} bits, got {}", message.len()));
    }
    println!();

    let code = private.code();
    let encoded = public.matrix().vec_mul(&message);
    let cipher = McEliece::encrypt_block(&message, public, &mut rng);
    let e = cipher.xor(&encoded);
    let positions: Vec<usize> = e.iter_ones().collect();

    println!("Encryption");
    println!("  m              : {}", grouped(&message));
    println!("  m·G'           : {}", grouped(&encoded));
    println!("  e (weight {:<3}) : {}", e.weight(), grouped(&e));
    println!("  e positions    : {positions:?}");
    println!("  c = m·G' + e   : {}", grouped(&cipher));

    let unpermuted = private.p_inv().apply(&cipher);
    let syndrome = code.syndrome(&unpermuted);
    let codeword = code.decode(&unpermuted)?;
    let fixed: Vec<usize> = unpermuted.xor(&codeword).iter_ones().collect();
    let message_s = code.message(&codeword);
    let decrypted = private.s_inv().vec_mul(&message_s);

    println!("Decryption");
    println!("  c·P⁻¹          : {}", grouped(&unpermuted));
    println!("  syndrome S(x)  : {}", syndrome.display(code.field()));
    println!("  fixed at       : {fixed:?} (e·P⁻¹)");
    println!("  m·S·G          : {}", grouped(&codeword));
    println!("  m·S (first k)  : {}", grouped(&message_s));
    println!("  m = m·S·S⁻¹    : {}", grouped(&decrypted));
    println!(
        "  result         : {}",
        if decrypted == message {
            "matches the message"
        } else {
            "MISMATCH"
        }
    );
    println!("  block sizes    : {k} bits in, {n} bits out");

    return Ok(());
}

fn main() {
    cli::init(env!("CARGO_MANIFEST_DIR"));
    let mut params = Params::ORIGINAL;
    let (mut private, mut public) = generate_keys(params).expect("the preset parameters are valid");
    let mut io_mode = IoMode::Text;

    loop {
        println!();
        println!(
            "{TITLE} — input/output: {}, n = {}, k = {}, t = {}",
            io_mode.name(),
            public.n(),
            public.k(),
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
            "g" => read_params(params).and_then(|new_params| {
                (private, public) = generate_keys(new_params)?;
                params = new_params;
                Ok(())
            }),
            "q" => break,
            _ => Err(format!("unknown choice: {choice:?}")),
        };

        if let Err(err) = result {
            println!("Error: {err}");
        }
    }
}
