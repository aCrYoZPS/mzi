use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::key::Key;

pub type CipherFn = fn(Vec<u8>, &Key<8>) -> Vec<u8>;
pub type MacFn = fn(Vec<u8>, &Key<8>, usize) -> Option<u64>;
/// Keyless, arbitrary width — a hash, unlike the keyed and truncatable MAC.
pub type DigestFn = fn(Vec<u8>) -> Vec<u8>;

/// A payload validation supplied by the cipher: it knows the block size, the
/// framing and the padding of its own mode, the CLI only reports what it says.
pub type Check = Box<dyn Fn(&[u8]) -> Result<(), String>>;

pub struct CipherMode {
    pub name: String,
    pub encrypt: CipherFn,
    pub decrypt: CipherFn,
    pub plaintext_check: Option<Check>,
    pub ciphertext_check: Option<Check>,
}

impl CipherMode {
    pub fn new(name: impl Into<String>, encrypt: CipherFn, decrypt: CipherFn) -> Self {
        return CipherMode {
            name: name.into(),
            encrypt,
            decrypt,
            plaintext_check: None,
            ciphertext_check: None,
        };
    }

    /// Runs before encryption, e.g. to reject inputs a ciphertext stealing mode
    /// is too short to process.
    pub fn checking_plaintext(
        mut self,
        check: impl Fn(&[u8]) -> Result<(), String> + 'static,
    ) -> Self {
        self.plaintext_check = Some(Box::new(check));

        return self;
    }

    /// Runs before decryption, e.g. to reject a ciphertext that cannot hold the
    /// framing the mode adds (a sync value, a padding byte).
    pub fn checking_ciphertext(
        mut self,
        check: impl Fn(&[u8]) -> Result<(), String> + 'static,
    ) -> Self {
        self.ciphertext_check = Some(Box::new(check));

        return self;
    }
}

pub struct MacSpec {
    pub compute: MacFn,
    pub default_bits: usize,
    pub max_bits: usize,
}

pub struct DigestSpec {
    pub name: &'static str,
    pub compute: DigestFn,
}

pub struct CipherApp {
    pub title: &'static str,
    pub encrypted_extension: &'static str,
    pub modes: Vec<CipherMode>,
    pub mac: Option<MacSpec>,
    pub digest: Option<DigestSpec>,
    pub default_key: Key<8>,
}

/// The menu entries that follow the per-mode encrypt/decrypt pairs.
enum Extra<'a> {
    Mac(&'a MacSpec),
    Digest(&'a DigestSpec),
}

impl Extra<'_> {
    fn label(&self) -> &'static str {
        match self {
            Extra::Mac(_) => "MAC",
            Extra::Digest(digest) => digest.name,
        }
    }
}

/// The one length rule every mode expresses in some form: a lower bound in
/// bytes. What the bound means is up to the caller.
pub fn at_least(min: usize) -> impl Fn(&[u8]) -> Result<(), String> {
    return move |bytes: &[u8]| {
        if bytes.len() < min {
            return Err(format!(
                "expected at least {min} bytes, got {}",
                bytes.len()
            ));
        }

        return Ok(());
    };
}

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

pub fn prompt(label: &str) -> String {
    print!("{label}");
    io::stdout().flush().expect("failed to flush stdout");

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .expect("failed to read stdin");

    return line.trim_end_matches(['\r', '\n']).to_string();
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02X}"));
    }

    return hex;
}

pub fn from_hex(text: &str) -> Result<Vec<u8>, String> {
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

pub fn parse_key(hex_key: &str) -> Result<Key<8>, String> {
    if hex_key.len() != 64 {
        return Err("valid key should be 256 bits (64 characters)".to_string());
    }

    let bytes = from_hex(hex_key)?;
    let mut new_key = [0u32; 8];
    for (idx, word) in bytes.chunks(4).enumerate() {
        new_key[idx] = u32::from_le_bytes(word.try_into().expect("64 hex digits give 8 words"));
    }

    return Ok(Key(new_key));
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    return fs::read(path).map_err(|err| format!("cannot read {}: {err}", path.display()));
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    return fs::write(path, bytes).map_err(|err| format!("cannot write {}: {err}", path.display()));
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

impl CipherApp {
    fn default_output_path(&self, source: &Path, encrypt: bool) -> PathBuf {
        if encrypt {
            let mut name = source.as_os_str().to_os_string();
            name.push(format!(".{}", self.encrypted_extension));

            return PathBuf::from(name);
        }

        if source
            .extension()
            .is_some_and(|ext| ext == self.encrypted_extension)
        {
            return source.with_extension("");
        }

        let mut name = source.as_os_str().to_os_string();
        name.push(".decrypted");

        return PathBuf::from(name);
    }

    fn read_payload(
        &self,
        io_mode: IoMode,
        encrypt: bool,
    ) -> Result<(Vec<u8>, Option<PathBuf>), String> {
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
        &self,
        io_mode: IoMode,
        encrypt: bool,
        mode: &CipherMode,
        key: &Key<8>,
    ) -> Result<(), String> {
        let cipher_fn = if encrypt { mode.encrypt } else { mode.decrypt };

        let (input, source) = self.read_payload(io_mode, encrypt)?;
        if input.is_empty() {
            return Err("nothing to process: the input is empty".to_string());
        }

        let (check, kind) = if encrypt {
            (&mode.plaintext_check, "plaintext")
        } else {
            (&mode.ciphertext_check, "ciphertext")
        };
        if let Some(check) = check {
            check(&input).map_err(|err| format!("{} {kind}: {err}", mode.name))?;
        }

        let destination = match &source {
            Some(path) => Some(ask_output_path(&self.default_output_path(path, encrypt))?),
            None => None,
        };

        let output = cipher_fn(input.clone(), key);

        println!(
            "  mode      : {} ({})",
            mode.name,
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

    fn run_mac(&self, io_mode: IoMode, mac: &MacSpec, key: &Key<8>) -> Result<(), String> {
        let (message, source) = self.read_payload(io_mode, true)?;

        let bits_input = prompt(&format!("MAC length in bits [{}]: ", mac.default_bits));
        let mac_bits = if bits_input.is_empty() {
            mac.default_bits
        } else {
            match bits_input.parse::<usize>() {
                Ok(bits) if (1..=mac.max_bits).contains(&bits) => bits,
                _ => {
                    return Err(format!(
                        "MAC length must be an integer in 1..={}",
                        mac.max_bits
                    ));
                }
            }
        };

        let mac_value = (mac.compute)(message.clone(), key, mac_bits)
            .ok_or_else(|| "an empty message has no MAC".to_string())?;

        match source {
            Some(path) => println!("  message : {} ({} bytes)", path.display(), message.len()),
            None => println!("  message : {} bytes", message.len()),
        }
        println!(
            "  mac     : {mac_value:0width$X} ({mac_bits} bits)",
            width = mac_bits.div_ceil(4)
        );

        return Ok(());
    }

    fn run_digest(&self, io_mode: IoMode, digest: &DigestSpec) -> Result<(), String> {
        let (message, source) = self.read_payload(io_mode, true)?;

        let value = (digest.compute)(message.clone());

        match source {
            Some(path) => println!("  message : {} ({} bytes)", path.display(), message.len()),
            None => println!("  message : {} bytes", message.len()),
        }
        println!(
            "  {:<8}: {} ({} bits)",
            digest.name,
            to_hex(&value),
            value.len() * 8
        );

        return Ok(());
    }

    fn extras(&self) -> Vec<Extra<'_>> {
        let mut extras: Vec<Extra<'_>> = Vec::new();
        if let Some(mac) = &self.mac {
            extras.push(Extra::Mac(mac));
        }
        if let Some(digest) = &self.digest {
            extras.push(Extra::Digest(digest));
        }

        return extras;
    }

    fn print_menu(&self, io_mode: IoMode) {
        println!();
        println!("{} — input/output: {}", self.title, io_mode.name());

        let modes = self.modes.len();
        for (idx, mode) in self.modes.iter().enumerate() {
            let left = format!("{}) encrypt ({})", idx + 1, mode.name);
            println!("{left:<22}{}) decrypt ({})", idx + 1 + modes, mode.name);
        }
        for (idx, extra) in self.extras().iter().enumerate() {
            println!("{}) {}", 2 * modes + 1 + idx, extra.label());
        }
    }

    pub fn run(&self) {
        let mut key = self.default_key;
        let mut io_mode = IoMode::Text;
        let modes = self.modes.len();
        let extras = self.extras();

        loop {
            self.print_menu(io_mode);

            let choice = prompt(
                "Choice (or 'm' to switch text/file mode, 'k' to see key, 'c' to change key, 'q' to quit): ",
            );
            println!();

            let result = match choice.as_str() {
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
                _ => match choice.parse::<usize>() {
                    Ok(n) if (1..=modes).contains(&n) => {
                        self.run_cipher(io_mode, true, &self.modes[n - 1], &key)
                    }
                    Ok(n) if (modes + 1..=2 * modes).contains(&n) => {
                        self.run_cipher(io_mode, false, &self.modes[n - modes - 1], &key)
                    }
                    Ok(n) if (2 * modes + 1..=2 * modes + extras.len()).contains(&n) => {
                        match extras[n - 2 * modes - 1] {
                            Extra::Mac(mac) => self.run_mac(io_mode, mac, &key),
                            Extra::Digest(digest) => self.run_digest(io_mode, digest),
                        }
                    }
                    _ => Err(format!("unknown choice: {choice:?}")),
                },
            };

            if let Err(err) = result {
                println!("Error: {err}");
            }
        }
    }
}
