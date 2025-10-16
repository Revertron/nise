use anyhow::{anyhow, Context, Error};
use nitrokey_piv::{from_hex, parse_certificate_subject, to_hex, wrap_key, CertificateSubject, EccCurve, Nitrokey3PIV, PivSlot, PublicKey, DEFAULT_ADMIN_KEY};
use std::convert::TryFrom;
use std::str::FromStr;
use std::{env, io, process};

use rand::rngs::OsRng;
use rand::RngCore;

use p256::ecdh::SharedSecret as P256SharedSecret;
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use p384::ecdh::SharedSecret as P384SharedSecret;
use p384::{PublicKey as P384PublicKey, SecretKey as P384SecretKey};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{Key as XKey, KeyInit, XChaCha20Poly1305, XNonce};
use getopts::Options;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

// Encryption chunk size (1 MiB)
const CHUNK_SIZE: usize = 1024 * 1024;

// Include key management help text
const KEY_MANAGEMENT_HELP: &str = include_str!("../key_management_help.txt");

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = &args[0];

    let mut opts = Options::new();

    // Define CLI options
    opts.optflag("i", "init", "Init PIV slot with certificate + keypair");
    opts.optflag("e", "encode", "Encrypt file for given keys");
    opts.optflag("d", "decode", "Decrypt file using Nitrokey");
    opts.optopt("c", "certificate", "Certificate subject line", "CN=Alice, O=My corp, OU=Department, C=US");
    opts.optmulti("k", "key", "Key string (repeatable)", "KEY");
    opts.optopt("s", "slot", "Slot ID in hex format (82 to 95)", "SLOT_HEX");
    opts.optopt("f", "file", "Input file path", "FILE");
    opts.optopt("o", "output", "Output file path", "OUT");
    opts.optflag("", "set-pin", "Set PIN key for PIV applet");
    opts.optflag("", "set-puk", "Set Pin Unlock Key for PIV applet");
    opts.optflag("", "set-admin-key", "Set Admin Key for PIV applet");
    opts.optflag("h", "help", "Print this help menu");

    // Parse args
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            eprintln!("Error parsing options: {}", f);
            eprintln!("{}", opts.usage(&format!("Usage: {} [options]", prog)));
            process::exit(1);
        }
    };

    if matches.opt_present("h") {
        println!("{}", opts.usage(&format!("Usage: {} [options]", prog)));
        println!("\n{}", KEY_MANAGEMENT_HELP);
        return;
    }

    if matches.opt_present("set-pin") {
        if matches.opt_present("e") || matches.opt_present("d") || matches.opt_present("i") {
            eprintln!("Cannot combine with other tools.");
            process::exit(1);
        }

        let pin = prompt_current_credential("Enter current user PIN (default: 123456): ", "123456")
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                process::exit(1);
            });

        let nk = Nitrokey3PIV::open(None).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(1);
        });

        if let Err(e) = change_pin(&nk, &pin) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
        return;
    }

    if matches.opt_present("set-puk") {
        if matches.opt_present("e") || matches.opt_present("d") || matches.opt_present("i") {
            eprintln!("Cannot combine with other tools.");
            process::exit(1);
        }

        let old_puk = prompt_current_credential("Enter current PUK (default: 12345678): ", "12345678")
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                process::exit(1);
            });

        let nk = Nitrokey3PIV::open(None).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(1);
        });

        if let Err(e) = change_puk(&nk, &old_puk) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
        return;
    }

    if matches.opt_present("set-admin-key") {
        if matches.opt_present("e") || matches.opt_present("d") || matches.opt_present("i") {
            eprintln!("Cannot combine with other tools.");
            process::exit(1);
        }

        let nk = Nitrokey3PIV::open(None).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            process::exit(1);
        });

        match set_password_as_admin_key(&nk) {
            Ok(_) => println!("Admin key changed successfully!"),
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        };
        return;
    }

    // Mode: init
    if matches.opt_present("i") {
        if matches.opt_present("e") || matches.opt_present("d") {
            eprintln!("Cannot combine --init with --encode or --decode.");
            process::exit(1);
        }

        let slot_name = match matches.opt_str("s") {
            None => {
                eprintln!("Define slot ID using --slot/-s parameter.");
                process::exit(1);
            }
            Some(slot) => slot
        };
        let slot_byte = match from_hex(&slot_name) {
            Ok(x) => {
                if x.len() != 1 {
                    eprintln!("Error parsing slot number. Use only 82 to 95 in hex.");
                    process::exit(1);
                }
                if x[0] < 0x82 || x[0] > 0x95 {
                    eprintln!("You can't use slot {slot_name} in nise. Use only 82 to 95 in hex.");
                    process::exit(1);
                }
                x[0]
            }
            Err(e) => {
                eprintln!("{e}. Use only 82 to 95 in hex.");
                process::exit(1);
            }
        };
        let slot = PivSlot::try_from(slot_byte).unwrap();

        let nk = match Nitrokey3PIV::open(None) {
            Ok(nk) => nk,
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        };

        let subj = match matches.opt_str("c") {
            None => {
                println!("\nNo certificate info given. Please enter certificate fields manually.");

                let common_name = prompt("Common Name (CN)", Some("NISE1"));
                let organization = prompt_optional("Organization (O)");
                let organizational_unit = prompt_optional("Organizational Unit (OU)");
                let country = prompt_optional("Country (C)");

                CertificateSubject {
                    common_name,
                    organization,
                    organizational_unit,
                    country,
                }
            },
            Some(s) => {
                match parse_certificate_subject(&s) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        process::exit(1);
                    }
                }
            }
        };

        println!();

        println!("For key-pair generation we need to authenticate with Admin Key");
        if let Err(e) = auth_admin(&nk) {
            eprintln!("Admin authentication failed: {}", e);
            process::exit(1);
        }
        println!("Admin authentication succeeded\n");

        let mut pin = prompt_current_credential("Enter user PIN for certificate signing (default: 123456): ", "123456")
            .unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                process::exit(1);
            });

        if pin == "123456" {
            println!("\nWarning! You are using default PIN, it is not secure!");
            pin = change_pin(&nk, &pin).unwrap_or_else(|e| {
                eprintln!("Error: {}", e);
                process::exit(1);
            });
        }

        if let Err(_) = nk.verify_pin(&pin) {
            eprintln!("Failed to verify user PIN!");
            process::exit(1);
        }

        print!("Generating keys and certificate... ");
        io::stdout().flush().unwrap();
        match nk.generate_key_and_cert(slot, &subj, EccCurve::P256, 365 * 100) {
            Err(e) => {
                println!();
                eprintln!("Error: {}", e);
                process::exit(1);
            }
            Ok(pub_key) => {
                println!("Done!\n");
                let pub_hex = to_hex(&pub_key.to_uncompressed_point());
                println!("Your decryption key:\nnise1:{:X}:{:X}:{pub_hex}", nk.get_serial(), slot.as_u8());
            }
        }
        return;
    }

    // Mode: ENCODE
    if matches.opt_present("e") {
        let keys = matches.opt_strs("k");
        if keys.is_empty() {
            eprintln!("--encode requires at least one --key/-k parameter.");
            process::exit(1);
        }

        let infile = match matches.opt_str("f") {
            Some(s) => s,
            None => {
                eprintln!("--encode requires --file/-f.");
                process::exit(1);
            }
        };
        let outfile = match matches.opt_str("o") {
            Some(s) => s,
            None => {
                eprintln!("--encode requires --output/-o.");
                process::exit(1);
            }
        };

        let keys = keys
            .iter()
            .map(|s| s.parse::<NiseKey>())
            .filter(|k| k.is_ok())
            .map(|k| k.unwrap())
            .collect::<Vec<NiseKey>>();

        if let Err(e) = encrypt_file(&infile, &outfile, &keys) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
        return;
    }

    // Mode: DECODE
    if matches.opt_present("d") {
        let infile = match matches.opt_str("f") {
            Some(s) => s,
            None => {
                eprintln!("--decode requires --file/-f.");
                process::exit(1);
            }
        };
        let outfile = match matches.opt_str("o") {
            Some(s) => s,
            None => {
                eprintln!("--decode requires --output/-o.");
                process::exit(1);
            }
        };

        let lambda = |serial: u32, slot_byte: u8, recipient_pub: Vec<u8>, eph_pub: Vec<u8>| -> anyhow::Result<Vec<u8>> {
            // Open device by serial
            let dev = Nitrokey3PIV::open(Some(serial))?;

            // Check keypair
            let slot = PivSlot::try_from(slot_byte)?;
            let stored_pub = dev.read_public_key(slot)?;
            if let Some(pub_key) = stored_pub {
                if pub_key != recipient_pub {
                    return Err(anyhow::anyhow!("Slot does not match stored key"));
                }
            }

            // Verify PIN
            match rpassword::prompt_password("Enter user PIN (123456):") {
                Ok(p) => {
                    if p.is_empty() {
                        dev.verify_pin("123456")?;
                    } else {
                        dev.verify_pin(&p)?;
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }

            // Compute ECDH
            let shared = dev.ecdh_unwrapped(slot, &eph_pub)?;
            Ok(shared)
        };

        if let Err(e) = decrypt_file_with_device(&infile, &outfile, lambda) {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
        return;
    }

    // No valid mode given
    eprintln!("No operation specified. Use one of --init, --encode, or --decode.");
    eprintln!("{}", opts.usage(&format!("Usage: {} [options]", prog)));
    process::exit(1);

}

// ============================================================================
// Credential Management Helper Functions
// ============================================================================

/// Prompts user for yes/no confirmation
fn confirm(prompt: &str) -> anyhow::Result<bool> {
    print!("{} [y/N]: ", prompt);
    io::stdout().flush()?;

    let mut response = String::new();
    io::stdin().read_line(&mut response)?;

    let answer = response.trim().to_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Prompts for a secret value with confirmation and validation
fn prompt_secret_with_confirmation(
    prompt: &str,
    confirm_prompt: &str,
    validator: impl Fn(&str) -> Result<(), String>,
) -> anyhow::Result<String> {
    loop {
        let secret = rpassword::prompt_password(prompt)
            .context("Failed to read password")?;

        // Validate the input
        if let Err(msg) = validator(&secret) {
            eprintln!("{}", msg);
            continue;
        }

        // Confirm the secret
        let confirmation = rpassword::prompt_password(confirm_prompt)
            .context("Failed to read confirmation")?;

        if secret != confirmation {
            eprintln!("Entries do not match. Please try again.");
            continue;
        }

        return Ok(secret);
    }
}

/// Prompts for current credential with default fallback
fn prompt_current_credential(prompt: &str, default: &str) -> anyhow::Result<String> {
    let value = rpassword::prompt_password(prompt)
        .context("Failed to read password")?;

    if value.is_empty() {
        println!("Using default: {}", default);
        Ok(default.to_string())
    } else {
        Ok(value)
    }
}

/// Validates PIN format (6-8 characters)
fn validate_pin(pin: &str) -> Result<(), String> {
    if pin.len() < 6 || pin.len() > 8 {
        Err("PIN must be 6-8 characters long.".to_string())
    } else {
        Ok(())
    }
}

/// Validates PUK format (6-8 characters)
fn validate_puk(puk: &str) -> Result<(), String> {
    if puk.len() < 6 || puk.len() > 8 {
        Err("PUK must be 6-8 characters long.".to_string())
    } else {
        Ok(())
    }
}

/// Validates password is non-empty
fn validate_password(password: &str) -> Result<(), String> {
    if password.trim().is_empty() {
        Err("Password cannot be empty.".to_string())
    } else {
        Ok(())
    }
}

/// Validates hex key format (must be 32, 48, or 64 hex characters for 16/24/32 bytes)
fn validate_hex_key(hex: &str) -> Result<(), String> {
    let hex = hex.trim();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Key must contain only hexadecimal characters (0-9, a-f, A-F).".to_string());
    }
    match hex.len() {
        32 | 48 | 64 => Ok(()), // 16, 24, or 32 bytes
        _ => Err("Key must be 32, 48, or 64 hex characters (16, 24, or 32 bytes).".to_string()),
    }
}

/// Changes the user PIN on the device
fn change_pin(nk: &Nitrokey3PIV, old_pin: &str) -> anyhow::Result<String> {
    if !confirm("Do you want to change the PIN?")? {
        println!("PIN change cancelled.");
        return Ok(old_pin.to_string());
    }

    let new_pin = prompt_secret_with_confirmation(
        "Enter new user PIN (6-8 characters): ",
        "Enter new PIN again: ",
        validate_pin,
    )?;

    nk.change_pin(old_pin, &new_pin)
        .context("Failed to change PIN on device")?;

    println!("PIN changed successfully!");
    Ok(new_pin)
}

/// Changes the PUK on the device
fn change_puk(nk: &Nitrokey3PIV, old_puk: &str) -> anyhow::Result<()> {
    if !confirm("Do you want to change the PUK?")? {
        println!("PUK change cancelled.");
        return Ok(());
    }

    let new_puk = prompt_secret_with_confirmation(
        "Enter new PUK (6-8 characters): ",
        "Enter new PUK again: ",
        validate_puk,
    )?;

    nk.change_puk(old_puk, &new_puk)
        .context("Failed to change PUK on device")?;

    println!("PUK changed successfully!");
    Ok(())
}

/// Prompts for the current admin key (supports hex, password, or default)
fn prompt_current_admin_key(nk: &Nitrokey3PIV) -> anyhow::Result<Vec<u8>> {
    let input = rpassword::prompt_password("Enter current admin key (default: 0102030405060708 x 3): ")
        .context("Failed to read admin key")?;

    if input.is_empty() {
        return Ok(DEFAULT_ADMIN_KEY.to_vec());
    }

    // Try to parse as hex
    if let Ok(key) = from_hex(&input) {
        match key.len() {
            16 | 24 | 32 => return Ok(key),
            _ => return Err(anyhow!("Key size mismatch, should be 16/24/32 bytes long.")),
        }
    }

    // Not hex, treat as password
    println!("Treating input as password (not hex)...");
    let guid = nk.guid().context("Failed to get card GUID")?;
    let key = wrap_key(input.as_bytes(), None, &guid);
    Ok(key.to_vec())
}

/// Sets a new admin key (password-derived or hex)
fn set_password_as_admin_key(nk: &Nitrokey3PIV) -> anyhow::Result<Vec<u8>> {
    if !confirm("Do you want to change the admin key?")? {
        return Err(anyhow!("Admin key change canceled"));
    }

    println!("\nChoose admin key method:");
    println!("  1) Derive from password (device-specific, may seem like vendor-locked)");
    println!("  2) Set from hex bytes (portable, generate with: openssl rand -hex 32, or some sha256 hash)");
    print!("\nEnter choice [1/2]: ");
    io::stdout().flush()?;

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let key = match choice {
        "1" => {
            // Password-derived key (device-specific via GUID)
            let password = prompt_secret_with_confirmation(
                "Enter new admin password: ",
                "Enter password again: ",
                validate_password,
            )?;

            let guid = nk.guid().context("Failed to get card GUID")?;
            wrap_key(password.as_bytes(), None, &guid).to_vec()
        }
        "2" => {
            // Direct hex key input
            let hex_key = prompt_secret_with_confirmation(
                "Enter admin key in hex (32, 48, or 64 characters for AES-128/3DES/AES-256 respectively): ",
                "Enter hex key again: ",
                validate_hex_key,
            )?;

            from_hex(&hex_key.trim())
                .context("Failed to parse hex key")?
        }
        _ => {
            return Err(anyhow!("Invalid choice. Admin key change canceled."));
        }
    };

    nk.set_admin_key(&key)
        .context("Failed to set admin key on device")?;

    Ok(key)
}

/// Authenticates with admin key and prompts to upgrade if using default
fn auth_admin(nk: &Nitrokey3PIV) -> anyhow::Result<()> {
    let mut admin_key = prompt_current_admin_key(nk)?;

    // Warn if using default and offer to change
    if admin_key == DEFAULT_ADMIN_KEY {
        println!("\nWarning! You are using the default admin key. This is not secure!");

        if let Ok(new_key) = set_password_as_admin_key(nk) {
            admin_key = new_key;
        }
        // If user cancelled (returned Err), continue with default admin key
    }

    nk.auth_admin(&admin_key)
        .context("Failed to authenticate with admin key")?;

    Ok(())
}

fn prompt(label: &str, default: Option<&str>) -> String {
    let mut input = String::new();
    if let Some(def) = default {
        print!("  {} [{}]: ", label, def);
    } else {
        print!("  {}: ", label);
    }
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.unwrap_or("").to_string()
    } else {
        trimmed.to_string()
    }
}

fn prompt_optional(label: &str) -> Option<String> {
    let mut input = String::new();
    print!("  {} (optional): ", label);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::{decrypt_file_with_device, encrypt_file, NiseKey};
    use anyhow::Context;
    use nitrokey_piv::{to_hex, Nitrokey3PIV, PivSlot};
    use std::str::FromStr;

    pub fn encrypt() {
        println!("Encrypting...");
        let identity = NiseKey::from_str("nise1:52F743:85:0440F98EF5FDA26550A97E23CEDC3546D9A26F2494754F3F133CA0B954512AB1DDE40A051B4B050DEA6D0F273BA86AA66B8C1392823BDBB0B05F77EA71215640AF").unwrap();
        let result = encrypt_file("test_file.mp4", "encrypted_file.nise", &vec![identity]);
        assert!(result.is_ok());
    }

    pub fn decrypt() {
        println!("Decrypting...");
        let lambda = |serial: u32, slot_byte: u8, recipient_pub: Vec<u8>, eph_pub: Vec<u8>| -> anyhow::Result<Vec<u8>> {
            // 1. Open device by serial
            let dev = Nitrokey3PIV::open(Some(serial))?;

            // 2. Check keypair
            let slot = PivSlot::try_from(slot_byte)?;
            let stored_pub = dev.read_public_key(slot)?;
            println!("Recipient pub key: {}", to_hex(&recipient_pub));
            if let Some(pub_key) = stored_pub {
                println!("Stored public key: {}", to_hex(&pub_key));
                if pub_key != recipient_pub {
                    return Err(anyhow::anyhow!("slot does not match stored key"));
                }
            }

            // 3. Verify PIN
            dev.verify_pin("123456")?;

            // 4. Compute ECDH
            let shared = dev.ecdh_unwrapped(slot, &eph_pub)?;
            Ok(shared)
        };

        // call decryption
        let result = decrypt_file_with_device("encrypted_file.nise", "decrypted.mp4", lambda)
            .context("Decrypting file");
        assert!(result.is_ok());
    }
}

/// Nise (recipient) key
pub struct NiseKey {
    serial: u32,
    slot: PivSlot,
    pub_key: PublicKey
}

impl FromStr for NiseKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        // must start with "nise1:"
        let rest = s.strip_prefix("nise1:")
            .ok_or_else(|| anyhow!("missing nise1: prefix"))?;

        // split on ':'
        let mut parts = rest.splitn(4, ':');
        let hex_serial = parts.next().context("missing serial")?;
        let hex_slot   = parts.next().context("missing slot")?;
        let hex_point  = parts.next().context("missing public-key")?;

        // parse serial (u32)
        let serial = u32::from_str_radix(hex_serial, 16)
            .map_err(|e| anyhow!("invalid serial: {}", e))?;

        // parse slot (u8 → PivSlot)
        let slot_byte = u8::from_str_radix(hex_slot, 16)
            .map_err(|e| anyhow!("invalid slot: {}", e))?;
        let slot = PivSlot::try_from(slot_byte)
            .map_err(|_| anyhow!("unknown slot 0x{:02X}", slot_byte))?;

        // parse uncompressed point
        let point = hex::decode(hex_point)
            .map_err(|e| anyhow!("hex decode error: {}", e))?;
        let pub_key = PublicKey::try_from(point.as_slice())?; // re-uses your TryFrom impl

        Ok(NiseKey { serial, slot, pub_key })
    }
}

/// Helper: write unsigned LEB128 (varint)
fn write_uleb128(mut val: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (val & 0x7F) as u8;
        val >>= 7;
        if val != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
}

/// Main function: encrypt plaintext file `from` -> write `to`, for `ids` recipients.
pub fn encrypt_file<P1, P2>(from: P1, to: P2, ids: &[NiseKey]) -> Result<(), Error> where P1: AsRef<Path>, P2: AsRef<Path> {
    let mut rng = OsRng;
    // Generate file key (32 bytes) for AES-256-GCM
    let mut file_key = [0u8; 32];
    rng.fill_bytes(&mut file_key);

    // Prepare header buffer
    let mut header = Vec::new();
    header.extend_from_slice(b"nise1");

    // recipients count as varint
    write_uleb128(ids.len() as u64, &mut header);

    // For each recipient: compute ephemeral key, shared secret, wrap file_key
    struct RecRecord {
        serial_be: [u8;4],
        slot_byte: u8,
        recipient_pub: Vec<u8>,    // uncompressed point
        eph_pub: Vec<u8>,          // ephemeral uncompressed
        wrap_nonce: [u8;24],
        wrapped: Vec<u8>,
    }

    let mut recs: Vec<RecRecord> = Vec::with_capacity(ids.len());

    for nid in ids {
        let serial_be = nid.serial.to_be_bytes();
        let slot_byte: u8 = nid.slot.as_u8();

        // recipient public key as uncompressed point (0x04 || x || y)
        let recipient_pub = nid.pub_key.to_uncompressed_point();

        // depending on curve, construct PublicKey and ephemeral secret
        match nid.pub_key.curve {
            EccCurve::P256 => {
                // parse recipient pubkey as EncodedPoint
                let enc = p256::EncodedPoint::from_bytes(&recipient_pub)
                    .map_err(|e| anyhow::anyhow!("invalid p256 recipient public key: {e}"))?;
                let rec_pub = P256PublicKey::from_sec1_bytes(enc.as_bytes())
                    .context("failed to construct p256 public key")?;

                // ephemeral secret (random)
                let eph_sk = P256SecretKey::random(&mut rng);
                let eph_pk = eph_sk.public_key();

                // compute shared secret
                let shared: P256SharedSecret = p256::ecdh::diffie_hellman(
                    eph_sk.to_nonzero_scalar(),
                    rec_pub.as_affine()
                );

                // shared.as_bytes() yields x-coordinate big-endian
                let shared_bytes = shared.raw_secret_bytes().as_slice();

                let mut info = Vec::new();
                info.extend_from_slice(eph_pk.to_encoded_point(false).as_bytes());
                info.extend_from_slice(recipient_pub.as_slice());
                // derive symmetric key
                let sym = wrap_key(shared_bytes, None, &info);

                // XChaCha20-Poly1305 encrypt the file_key
                let xkey = XKey::from_slice(&sym);
                let aead = XChaCha20Poly1305::new(xkey);

                let mut wrap_nonce = [0u8; 24];
                rng.fill_bytes(&mut wrap_nonce);
                let nonce = XNonce::from_slice(&wrap_nonce);

                let wrapped = aead
                    .encrypt(nonce, file_key.as_ref())
                    .map_err(|e| anyhow::anyhow!("wrap file key with xchacha20 failed: {e}"))?;

                let eph_bytes = eph_pk.to_encoded_point(false).as_bytes().to_vec();

                recs.push(RecRecord {
                    serial_be,
                    slot_byte,
                    recipient_pub,
                    eph_pub: eph_bytes,
                    wrap_nonce,
                    wrapped,
                });
            }

            EccCurve::P384 => {
                // p384
                let enc = p384::EncodedPoint::from_bytes(&recipient_pub)
                    .map_err(|e| anyhow::anyhow!("invalid p384 recipient public key: {e}"))?;
                let rec_pub = P384PublicKey::from_sec1_bytes(enc.as_bytes())
                    .context("failed to construct p384 public key")?;

                let eph_sk = P384SecretKey::random(&mut OsRng);
                let eph_pk = eph_sk.public_key();

                let shared: P384SharedSecret = p384::ecdh::diffie_hellman(
                    eph_sk.to_nonzero_scalar(),
                    rec_pub.as_affine()
                );

                let shared_bytes = shared.raw_secret_bytes().as_slice();

                let mut info = Vec::new();
                info.extend_from_slice(eph_pk.to_encoded_point(false).as_bytes());
                info.extend_from_slice(recipient_pub.as_slice());
                // derive symmetric key
                let sym = wrap_key(shared_bytes, None, &info);

                let xkey = XKey::from_slice(&sym);
                let aead = XChaCha20Poly1305::new(xkey);

                let mut wrap_nonce = [0u8; 24];
                rng.fill_bytes(&mut wrap_nonce);
                let nonce = XNonce::from_slice(&wrap_nonce);

                let wrapped = aead
                    .encrypt(nonce, file_key.as_ref())
                    .map_err(|e| anyhow::anyhow!("wrap file key with xchacha20 failed: {e}"))?;

                let eph_bytes = eph_pk.to_encoded_point(false).as_bytes().to_vec();

                recs.push(RecRecord {
                    serial_be,
                    slot_byte,
                    recipient_pub,
                    eph_pub: eph_bytes,
                    wrap_nonce,
                    wrapped,
                });
            }
        }
    }

    // Write recipient records into header
    for r in &recs {
        header.extend_from_slice(&r.serial_be);
        header.push(r.slot_byte);

        // write recipient pub key length (u16 BE) + bytes
        let rp_len = r.recipient_pub.len() as u16;
        header.extend_from_slice(&rp_len.to_be_bytes());
        header.extend_from_slice(&r.recipient_pub);

        // ephemeral pk length + bytes
        let eph_len = r.eph_pub.len() as u16;
        header.extend_from_slice(&eph_len.to_be_bytes());
        header.extend_from_slice(&r.eph_pub);

        // wrap nonce (24)
        header.extend_from_slice(&r.wrap_nonce);

        // wrapped key length (u16 BE) + ciphertext
        let wlen = r.wrapped.len() as u16;
        header.extend_from_slice(&wlen.to_be_bytes());
        header.extend_from_slice(&r.wrapped);
    }

    // === XChaCha20-Poly1305 encrypt the file contents with file_key ===
    use chacha20poly1305::{
        aead::{Aead, KeyInit}, Key as XKey, XChaCha20Poly1305,
        XNonce
    };

    let infile = File::open(from.as_ref()).context("open input")?;
    let mut reader = BufReader::new(infile);
    let outfile = File::create(to).context("create output")?;
    let mut writer = BufWriter::new(outfile);

    // write header first
    writer.write_all(&header).context("write header")?;

    // random 8-byte base for nonces
    let mut base_nonce = [0u8; 8];
    rng.fill_bytes(&mut base_nonce);

    let cipher = XChaCha20Poly1305::new_from_slice(&file_key)
        .expect("invalid XChaCha20 key length");

    let mut chunk_buf = vec![0u8; CHUNK_SIZE];
    let mut counter: u128 = 0; // 128-bit counter, enough for billions of chunks

    loop {
        let read_bytes = reader.read(&mut chunk_buf)?;
        if read_bytes == 0 {
            break; // EOF
        }

        // derive per-chunk 24-byte nonce = base_nonce[8] || counter_be[16]
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[..8].copy_from_slice(&base_nonce);
        nonce_bytes[8..].copy_from_slice(&counter.to_be_bytes());
        let nonce = XNonce::from_slice(&nonce_bytes);

        // encrypt this chunk
        let ciphertext = cipher
            .encrypt(nonce, &chunk_buf[..read_bytes])
            .map_err(|e| anyhow::anyhow!("XChaCha20-Poly1305 encryption failed: {e}"))?;

        // write nonce + length + ciphertext
        writer.write_all(&nonce_bytes)?;
        let clen = (ciphertext.len() as u32).to_be_bytes();
        writer.write_all(&clen)?;
        writer.write_all(&ciphertext)?;

        counter = counter.checked_add(1).context("nonce counter overflow")?;
    }

    writer.flush()?;

    Ok(())
}

/// Decrypt a file produced by `encrypt_file`.
///
/// The device lambda receives:
///   - `serial`: the device serial number found in the header
///   - `slot_byte`: the slot byte (as stored)
///   - `recipient_pub`: the public key bytes that were used for encryption
///   - `eph_pub`: the ephemeral public key bytes from the sender
///
/// The lambda must:
///   1. Open the correct device by `serial`.
///   2. Verify that the public key in that slot matches `recipient_pub`.
///   3. Perform `verify_pin()` on the device.
///   4. Perform `ecdh()` on the device using `eph_pub`.
///   5. Return the **raw shared secret bytes** from that ECDH.
pub fn decrypt_file_with_device<P1, P2, F>(
    input_path: P1,
    output_path: P2,
    mut device_lambda: F,
) -> Result<(), Error>
where
    P1: AsRef<Path>,
    P2: AsRef<Path>,
    F: FnMut(u32, u8, Vec<u8>, Vec<u8>) -> Result<Vec<u8>, Error>,
{
    // Open encrypted file
    let mut rdr = BufReader::new(File::open(input_path.as_ref()).context("open input file")?);

    // --- Magic check ---
    let mut magic = [0u8; 5];
    rdr.read_exact(&mut magic)?;
    if &magic != b"nise1" {
        return Err(anyhow!("invalid magic (not a nise1 file)"));
    }

    // --- Read ULEB128 function (same as in encryption) ---
    fn read_uleb128<R: Read>(r: &mut R) -> Result<u64, Error> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let mut b = [0u8; 1];
            r.read_exact(&mut b)?;
            value |= ((b[0] & 0x7F) as u64) << shift;
            if (b[0] & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(anyhow!("ULEB128 too large"));
            }
        }
        Ok(value)
    }

    let recipients = read_uleb128(&mut rdr).context("read recipient count")? as usize;

    // --- Read all recipient records ---
    struct Recipient {
        serial: u32,
        slot_byte: u8,
        recipient_pub: Vec<u8>,
        eph_pub: Vec<u8>,
        wrap_nonce: [u8; 24],
        wrapped: Vec<u8>,
    }

    let mut recs = Vec::with_capacity(recipients);
    let mut u16buf = [0u8; 2];

    for _ in 0..recipients {
        let mut serial_buf = [0u8; 4];
        rdr.read_exact(&mut serial_buf)?;
        let serial = u32::from_be_bytes(serial_buf);

        let mut slot_buf = [0u8; 1];
        rdr.read_exact(&mut slot_buf)?;
        let slot_byte = slot_buf[0];

        rdr.read_exact(&mut u16buf)?;
        let len_rec_pub = u16::from_be_bytes(u16buf) as usize;
        let mut recipient_pub = vec![0u8; len_rec_pub];
        rdr.read_exact(&mut recipient_pub)?;

        rdr.read_exact(&mut u16buf)?;
        let len_eph_pub = u16::from_be_bytes(u16buf) as usize;
        let mut eph_pub = vec![0u8; len_eph_pub];
        rdr.read_exact(&mut eph_pub)?;

        let mut wrap_nonce = [0u8; 24];
        rdr.read_exact(&mut wrap_nonce)?;

        rdr.read_exact(&mut u16buf)?;
        let len_wrapped = u16::from_be_bytes(u16buf) as usize;
        let mut wrapped = vec![0u8; len_wrapped];
        rdr.read_exact(&mut wrapped)?;

        recs.push(Recipient {
            serial,
            slot_byte,
            recipient_pub,
            eph_pub,
            wrap_nonce,
            wrapped,
        });
    }

    // --- Try each recipient via device lambda ---
    let mut file_key: Option<Vec<u8>> = None;

    for rec in recs {
        // Ask the lambda to perform on-device ECDH
        let shared_bytes =
            match device_lambda(rec.serial, rec.slot_byte, rec.recipient_pub.clone(), rec.eph_pub.clone()) {
                Ok(bytes) => bytes,
                Err(_) => continue, // if this device isn’t available or wrong key, skip
            };

        let mut info = Vec::new();
        info.extend_from_slice(rec.eph_pub.as_slice());
        info.extend_from_slice(rec.recipient_pub.as_slice());

        // Derive symmetric key using same KDF
        let sym_key = wrap_key(&shared_bytes, None, &info);
        let cipher = XChaCha20Poly1305::new(XKey::from_slice(&sym_key));

        if let Ok(unwrapped) = cipher.decrypt(XNonce::from_slice(&rec.wrap_nonce), rec.wrapped.as_ref()) {
            if unwrapped.len() == 32 {
                file_key = Some(unwrapped);
                break;
            }
        } else {
            println!("error decrypting file_key");
        }
    }

    let file_key = file_key.ok_or_else(|| anyhow!("no matching recipient found on connected devices"))?;

    // --- Now decrypt file body ---
    let body_cipher = XChaCha20Poly1305::new(XKey::from_slice(&file_key));
    let mut writer = BufWriter::new(File::create(output_path.as_ref()).context("create output")?);

    loop {
        let mut nonce = [0u8; 24];
        match rdr.read_exact(&mut nonce) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).context("reading chunk nonce"),
        }

        let mut lenbuf = [0u8; 4];
        rdr.read_exact(&mut lenbuf)?;
        let clen = u32::from_be_bytes(lenbuf) as usize;
        let mut cbuf = vec![0u8; clen];
        rdr.read_exact(&mut cbuf)?;

        let plain = body_cipher
            .decrypt(XNonce::from_slice(&nonce), cbuf.as_ref())
            .map_err(|e| anyhow!("body chunk decryption failed: {e}"))?;
        writer.write_all(&plain)?;
    }

    writer.flush()?;
    Ok(())
}