mod hashing;
use common::cli::{self, IoMode};
use hashing::gost34_11::Gost34_11;
use hashing::sha1::Sha1;

const TITLE: &str = "Hash functions";

struct Algorithm {
    name: &'static str,
    hash: fn(&[u8]) -> Vec<u8>,
}

const ALGORITHMS: [Algorithm; 3] = [
    Algorithm {
        name: "SHA-1",
        hash: Sha1::hash,
    },
    Algorithm {
        name: "GOST-256",
        hash: gost_256,
    },
    Algorithm {
        name: "GOST-512",
        hash: gost_512,
    },
];

fn as_byte_string(hash: fn(&[u8]) -> Vec<u8>, bytes: &[u8]) -> Vec<u8> {
    let message: Vec<u8> = bytes.iter().rev().copied().collect();
    let mut digest = hash(&message);
    digest.reverse();

    return digest;
}

fn gost_256(bytes: &[u8]) -> Vec<u8> {
    return as_byte_string(Gost34_11::hash_256, bytes);
}

fn gost_512(bytes: &[u8]) -> Vec<u8> {
    return as_byte_string(Gost34_11::hash_512, bytes);
}

const M2: &str = "d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2fa20f120ecee\
f0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efebfaeafb20c8e3eef0e5e2fb";

struct TestVector {
    algorithm: usize,
    label: &'static str,
    message: fn() -> Vec<u8>,
    digest: &'static str,
}

const TEST_VECTORS: [TestVector; 10] = [
    TestVector {
        algorithm: 0,
        label: "\"\"",
        message: || Vec::new(),
        digest: "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
    },
    TestVector {
        algorithm: 0,
        label: "\"abc\"",
        message: || b"abc".to_vec(),
        digest: "A9993E364706816ABA3E25717850C26C9CD0D89D",
    },
    TestVector {
        algorithm: 0,
        label: "\"abcdbcde...nopq\" (56 bytes)",
        message: || b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
        digest: "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
    },
    TestVector {
        algorithm: 0,
        label: "1 000 000 x \"a\"",
        message: || vec![b'a'; 1_000_000],
        digest: "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
    },
    TestVector {
        algorithm: 1,
        label: "\"\"",
        message: || Vec::new(),
        digest: "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB",
    },
    TestVector {
        algorithm: 1,
        label: "M1 (RFC 6986)",
        message: || b"012345678901234567890123456789012345678901234567890123456789012".to_vec(),
        digest: "9D151EEFD8590B89DAA6BA6CB74AF9275DD051026BB149A452FD84E5E57B5500",
    },
    TestVector {
        algorithm: 1,
        label: "M2 (RFC 6986)",
        message: || cli::from_hex(M2).expect("M2 is valid hex"),
        digest: "9DD2FE4E90409E5DA87F53976D7405B0C0CAC628FC669A741D50063C557E8F50",
    },
    TestVector {
        algorithm: 2,
        label: "\"\"",
        message: || Vec::new(),
        digest: "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7\
                 362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A",
    },
    TestVector {
        algorithm: 2,
        label: "M1 (RFC 6986)",
        message: || b"012345678901234567890123456789012345678901234567890123456789012".to_vec(),
        digest: "1B54D01A4AF5B9D5CC3D86D68D285462B19ABC2475222F35C085122BE4BA1FFA\
                 00AD30F8767B3A82384C6574F024C311E2A481332B08EF7F41797891C1646F48",
    },
    TestVector {
        algorithm: 2,
        label: "M2 (RFC 6986)",
        message: || cli::from_hex(M2).expect("M2 is valid hex"),
        digest: "1E88E62226BFCA6F9994F1F2D51569E0DAF8475A3B0FE61A5300EEE46D961376\
                 035FE83549ADA2B8620FCD7C496CE5B33F0CB9DDDC2B6460143B03DABAC9FB28",
    },
];

fn run_test_vectors() -> Result<(), String> {
    let mut failed = 0;
    for vector in &TEST_VECTORS {
        let algorithm = &ALGORITHMS[vector.algorithm];
        let digest = cli::to_hex(&(algorithm.hash)(&(vector.message)()));
        let passed = digest == vector.digest;
        if !passed {
            failed += 1;
        }

        println!(
            "  {:<8} {:<30} {}",
            algorithm.name,
            vector.label,
            if passed { "passed" } else { "FAILED" }
        );
        if !passed {
            println!("    expected : {}", vector.digest);
            println!("    got      : {digest}");
        }
    }

    if failed > 0 {
        return Err(format!(
            "{failed} of {} test vectors failed",
            TEST_VECTORS.len()
        ));
    }

    println!("  all {} test vectors passed", TEST_VECTORS.len());

    return Ok(());
}

fn read_message(io_mode: IoMode) -> Result<(Vec<u8>, String), String> {
    match io_mode {
        IoMode::Text => {
            let bytes = cli::prompt("Message: ").into_bytes();
            let description = format!("{} bytes", bytes.len());

            return Ok((bytes, description));
        }
        IoMode::File => {
            let path = cli::ask_input_path("File: ")?;
            let bytes = cli::read_file(&path)?;
            let description = format!("{} ({} bytes)", path.display(), bytes.len());

            return Ok((bytes, description));
        }
    }
}

fn run_hash(io_mode: IoMode, algorithms: &[Algorithm]) -> Result<(), String> {
    let (message, description) = read_message(io_mode)?;

    println!("  message  : {description}");
    for algorithm in algorithms {
        let digest = (algorithm.hash)(&message);
        println!(
            "  {:<9}: {} ({} bits)",
            algorithm.name,
            cli::to_hex(&digest),
            digest.len() * 8
        );
    }

    return Ok(());
}

fn main() {
    cli::init(env!("CARGO_MANIFEST_DIR"));
    let mut io_mode = IoMode::Text;

    loop {
        println!();
        println!("{TITLE} — input/output: {}", io_mode.name());
        println!(
            "{:<22}{:<22}{:<22}4) all",
            "1) SHA-1", "2) GOST-256", "3) GOST-512"
        );

        let choice = cli::prompt(
            "Choice (or 'm' to switch text/file mode, 't' to run test vectors, 'q' to quit): ",
        );
        println!();

        let result = match choice.as_str() {
            "1" | "2" | "3" => {
                let idx = choice.parse::<usize>().expect("matched a digit") - 1;
                run_hash(io_mode, &ALGORITHMS[idx..=idx])
            }
            "4" => run_hash(io_mode, &ALGORITHMS),
            "m" => {
                io_mode = io_mode.toggled();
                println!("Switched to {} mode", io_mode.name());
                Ok(())
            }
            "t" => run_test_vectors(),
            "q" => break,
            _ => Err(format!("unknown choice: {choice:?}")),
        };

        if let Err(err) = result {
            println!("Error: {err}");
        }
    }
}
