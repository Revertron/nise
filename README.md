# NISE — Nitrokey Simple Encryption

**NISE (Nitrokey Simple Encryption)** is a Rust-based command-line tool for secure file encryption and decryption using **Nitrokey PIV hardware tokens** for key management.

It provides simple, hardware-backed file protection using **ChaCha20-Poly1305** authenticated encryption via the PIV interface of a Nitrokey.

If you've heard of `age` utility, this is slightly better analog, using only Nitrokey (possible Yubikey and others).

---

## Features

- **Hardware-based encryption** — private keys are stored securely inside the Nitrokey.
- **ChaCha20-Poly1305 AEAD** for fast, modern symmetric encryption.
- **PIV integration** using `nitrokey-piv` for key operations.
- **Simple CLI** — easy to use from the command line for encryption and decryption.
- **Supports P-256 and P-384** curves for ECDH key exchange.

---

## Installation

### Prerequisites

- **Rust** (edition 2024 or later)
- **Nitrokey PIV** hardware token (e.g., Nitrokey 3)
- USB access permissions for Nitrokey
- Linux, macOS, or Windows

### Build from source

```bash
git clone https://github.com/Revertron/nise.git
cd nise
cargo build --release
```

The resulting binary will be located at:

```
target/release/nise
```

You can install it system-wide using:

```bash
cargo install --path .
```

---

## Nitrokey Setup and usage

Make sure your Nitrokey supports **PIV (Personal Identity Verification)**, Nitrokey 3 has this functionality.

> **⚠️ IMPORTANT: Security Setup Required**
> Before using NISE, you **must** change the default PIN, PUK, and admin key on your Nitrokey.
> Using default credentials is a **critical security risk**.
>
> **📖 Read the [Complete Setup Guide (SETUP.md)](./SETUP.md)** for detailed instructions and security best practices.

### Quick Security Setup

**Change default credentials immediately:**

```bash
# 1. Change admin key (MOST IMPORTANT - DO THIS FIRST!)
nise --set-admin-key

# 2. Change PIN (used for decryption)
nise --set-pin

# 3. Change PUK (emergency unlock key)
nise --set-puk
```

### Initialize keys in a slot

Initialize keys in any slot of PIV applet (85..95 in HEX):

```bash
nise -i -s 85
```

It will generate an **ECDH key pair** and certificate (signed by new private key) into given PIV slot and print your key-string.

Then you can send that key-string to any of your friends or colegues, or even publish on your website.

### Encrypt a file for someone

Anyone, who wants to send you a confidential file can do this:

```bash
nise -e -k <long key string starting from nise1> -f some-secret-file.txt -o file-to-send.nse
```

### Decrypt that file

On the other side recipient will recover the readable version of the file like that:
```bash
nise -d -f file-to-send.nse -o decrypted-secrets.txt
```

The decryption process will ask the user to enter your PIN (from Nitrokey).

---

## How It Works

1. On encryption:

    * A random **ChaCha20 key** is generated.
    * The Nitrokey performs **ECDH** with its private key and a generated ephemeral public key.
    * The derived shared secret encrypts the ChaCha20 key.
    * The file is encrypted using **ChaCha20-Poly1305**.
    * The encrypted key and nonce are prepended to the output.

2. On decryption:

    * The encrypted ChaCha20 key is recovered.
    * Nitrokey performs **ECDH** again with the ephemeral key to derive the same secret.
    * The ChaCha20 key is decrypted and used to decrypt the file.

---

## Dependencies

* [`nitrokey-piv`](https://github.com/Revertron/nitrokey-piv) — PIV interface
* [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)
* [`p256`](https://crates.io/crates/p256)
* [`p384`](https://crates.io/crates/p384)
* [`anyhow`](https://crates.io/crates/anyhow)
* [`getopts`](https://crates.io/crates/getopts)
* [`rpassword`](https://crates.io/crates/rpassword)
* [`hex`](https://crates.io/crates/hex)
* [`rand`](https://crates.io/crates/rand)

---

## Contributions

Pull requests and feedback are welcome!
If you have suggestions for improving hardware support or performance, open an issue on [GitHub](https://github.com/Revertron/nise/issues).

---

## License

MIT License © 2025 [Revertron](https://github.com/Revertron)

---

## Disclaimer

NISE is provided **“as is”** without warranty.
Always verify your Nitrokey PIN and key setup before encrypting critical data.

