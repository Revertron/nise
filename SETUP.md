# Nitrokey Setup Guide for NISE

This guide covers the essential steps for setting up your Nitrokey device for use with NISE (Nitrokey Simple Encryption).

## Table of Contents

- [Understanding PIV Credentials](#understanding-piv-credentials)
- [Why Changing Default Credentials is Critical](#why-changing-default-credentials-is-critical)
- [Initial Setup Workflow](#initial-setup-workflow)
- [Credential Management](#credential-management)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Understanding PIV Credentials

Your Nitrokey PIV (Personal Identity Verification) applet uses three types of credentials to protect your cryptographic keys:

### 1. **PIN (Personal Identification Number)**
- **Purpose**: User authentication for cryptographic operations
- **Default**: `123456`
- **Format**: 6-8 characters (usually digits, but alphanumeric allowed)
- **Used for**:
  - Signing certificates during key generation
  - Decrypting files
  - Accessing private keys for cryptographic operations
- **Lockout**: After 3 incorrect attempts, the PIN is locked and requires PUK to unlock

### 2. **PUK (PIN Unlock Key)**
- **Purpose**: Unblock a locked PIN and reset it
- **Default**: `12345678`
- **Format**: 6-8 characters (any printable characters)
- **Used for**:
  - Unlocking PIN after failed attempts
  - Emergency recovery
- **Lockout**: After 3 failed attempts, the device may require factory reset

### 3. **Admin Key (Management Key)**
- **Purpose**: Administrative operations on the PIV applet
- **Default**: `010203040506070801020304050607080102030405060708` (hex) - literally `0102030405060708` repeated 3 times
- **Format**: 16, 24, or 32 bytes (can be hex or password-based)
- **Used for**:
  - Generating new key pairs
  - Creating certificates
  - Modifying PIV slots
  - Changing the admin key itself

---

## Why Changing Default Credentials is Critical

### Security Implications

**Using default credentials is like leaving your house key under the welcome mat.**

1. **Default Values Are Public Knowledge**
   - The default PIN (`123456`), PUK (`12345678`), and admin key are documented in Nitrokey manuals
   - Anyone with physical access to your device can use these defaults
   - Malware or unauthorized software can attempt default credentials

2. **Risks of Not Changing Defaults**

   **Default PIN (`123456`):**
   - Anyone can decrypt your encrypted files if they get your Nitrokey
   - Unauthorized users can sign documents or certificates in your name
   - No real security benefit over unencrypted files

   **Default PUK (`12345678`):**
   - Attackers can unlock a deliberately-locked PIN
   - Your "last line of defense" is compromised
   - Cannot rely on PIN lockout as a security feature

   **Default Admin Key:**
   - Anyone can generate new keys in your PIV slots, overwriting your encryption keys
   - Attackers can modify certificates
   - Complete compromise of the device's cryptographic infrastructure
   - **You could lose access to encrypted files permanently if someone overwrites your keys**

---

## Initial Setup Workflow

### Step 1: Change the Admin Key (MOST IMPORTANT - DO THIS FIRST!)

The admin key protects your device from unauthorized key generation and modification.

```bash
nise --set-admin-key
```

**Why first?** Once you generate encryption keys, the admin key protects them from being overwritten or compromised.

**Process:**
1. You'll be asked: `Do you want to change the admin key? [y/N]:`
   - Enter `y`
2. Press Enter when prompted for current admin key (uses default)
3. Enter a strong password when prompted
4. Confirm the password

**Recommendations:**
- Use a **strong, unique passphrase** (minimum 12 characters)
- Include uppercase, lowercase, numbers, and symbols
- Store it securely (password manager, encrypted backup)
- **DO NOT LOSE THIS** - you'll need it if you want to add more key slots later

### Step 2: Change the PIN

The PIN is used every time you decrypt a file or use your private key.

```bash
nise --set-pin
```

**Process:**
1. You'll be asked: `Do you want to change the PIN? [y/N]:`
   - Enter `y`
2. Press Enter for current PIN (uses default `123456`)
3. Enter your new PIN (6-8 characters)
4. Confirm the new PIN

**Recommendations:**
- Choose something memorable but not obvious (not `1234567`, your birthday, etc.)
- You'll enter this frequently, so balance security with usability
- 8 characters is better than 6
- Numeric is standard, but alphanumeric is supported

### Step 3: Change the PUK

The PUK is your emergency unlock key.

```bash
nise --set-puk
```

**Process:**
1. You'll be asked: `Do you want to change the PUK? [y/N]:`
   - Enter `y`
2. Press Enter for current PUK (uses default `12345678`)
3. Enter your new PUK (6-8 characters)
4. Confirm the new PUK

**Recommendations:**
- Make it different from your PIN
- Store it securely - you only need it if PIN is locked
- Can use letters and symbols for added security

### Step 4: Initialize Your Encryption Slot

Now that your device is secured, generate your encryption key pair:

```bash
nise -i -s 85
```

This will:
1. Prompt for admin key (you'll use your new password-based key)
2. Prompt for PIN (you'll use your new PIN)
3. Generate an ECDH key pair in slot 0x85
4. Create a self-signed certificate
5. Display your public key string (starting with `nise1:`)

**Important Notes:**
- You can use slots 0x82 through 0x95 (hex)
- Each slot can hold one key pair
- Save your `nise1:...` key string - others need it to encrypt files for you
- **If you change the admin key later, you can still use existing keys** - the admin key only protects slot management, not key usage

---

## Credential Management

### Changing Credentials Later

You can change any credential at any time:

```bash
# Change PIN
nise --set-pin

# Change PUK
nise --set-puk

# Change admin key
nise --set-admin-key
```

### What Happens During Initialization

NISE automatically protects you during the `-i` (init) process:

1. **Admin Key Check**: When you run `nise -i -s 85`, NISE checks if you're using the default admin key
   - If you are, it **prompts** you to change it before continuing
   - This prevents accidentally using insecure defaults

2. **PIN Check**: After admin authentication, NISE checks if you're using the default PIN (`123456`)
   - If you are, it **prompts** you to change it
   - You can decline, but you'll see a security warning

### Recovering from PIN Lockout

If you enter the wrong PIN 3 times, it will be locked:

1. The device will reject the PIN
2. Use your PUK to unlock and reset the PIN:
   ```bash
   # This functionality may require additional tools
   # Check Nitrokey documentation for PIN unlock procedures
   ```

**Note**: Currently, NISE focuses on encryption/decryption. For PIN unlock via PUK, you may need to use Nitrokey's official tools like `nitropy` or `ykman`.

---

## Best Practices

### ✅ Do's

1. **Change all three credentials immediately** after receiving a new Nitrokey
2. **Store credentials securely**:
   - Use a password manager for PIN and admin key
   - Write down PUK and store in a safe place (fireproof safe, safety deposit box)
3. **Use different values** for PIN, PUK, and admin key
4. **Test decryption** after initial setup to ensure everything works
5. **Backup your credential information** in a secure location separate from the device
6. **Use strong admin key passwords** (12+ characters with mixed case, numbers, symbols)
7. **Keep the Nitrokey firmware updated** (check Nitrokey's official site)

### ❌ Don'ts

1. **Never leave default credentials unchanged**
2. **Don't share your PIN** with others
3. **Don't write down credentials on the device itself** or in the same location
4. **Don't use the same PIN across multiple devices**
5. **Don't choose obvious PINs** (123456, 111111, birthdays, etc.)
6. **Don't lose your admin key** - you may need it to manage slots in the future
7. **Don't skip changing the admin key** thinking "I'll do it later"

### Recommended Credential Strength

| Credential | Minimum | Recommended | Example (Pattern) |
|------------|---------|-------------|-------------------|
| PIN | 6 chars | 8 chars | `47829156` (random digits) |
| PUK | 6 chars | 8 chars | `kQ7$mP2x` (mixed) |
| Admin Key | 12 chars | 16+ chars | `MyN!tr0k3y#2025$SecurePass` (passphrase) |

---

## Troubleshooting

### "Admin authentication failed"
- **Cause**: Wrong admin key entered
- **Solution**:
  - If you just got the device, press Enter to use default
  - If you changed it, enter your password-based admin key
  - If you forgot it, you may need to factory reset the PIV applet (⚠️ destroys all keys)

### "Failed to verify user PIN"
- **Cause**: Wrong PIN entered
- **Solution**:
  - Try again (you have 3 attempts)
  - After 3 attempts, you'll need to use PUK to unlock
  - If you forgot PIN and PUK, factory reset required (⚠️ destroys all keys)

### "I forgot my admin key password"
- **Impact**: You cannot generate new keys or modify existing slots
- **Workaround**: Your existing encryption keys still work for decryption
- **Solution**: Factory reset PIV applet to regain admin access (⚠️ destroys all keys and encrypted data becomes unrecoverable)

### "I lost my Nitrokey but have backups of my keys"
- **NISE Design**: Private keys **cannot be exported** from Nitrokey (this is a security feature)
- **Reality**: If you lose the physical device, you **cannot decrypt files** encrypted for that device
- **Prevention**:
  - Encrypt files for multiple recipients (multiple Nitrokeys or backup devices)
  - Use the multi-recipient feature: `nise -e -k <key1> -k <key2> -f file.txt -o encrypted.nise`

### "Can I backup my private keys?"
- **No**: Nitrokey hardware enforces non-exportable private keys
- **This is intentional**: It's the core security feature of hardware tokens
- **Alternative**:
  - Set up multiple Nitrokeys with different keys
  - Encrypt important files for multiple recipients
  - Store one Nitrokey in a safe location as a "cold storage" backup

---

## Quick Setup Checklist

Use this checklist when setting up a new Nitrokey:

- [ ] Received Nitrokey and verified it's genuine (check packaging/seals)
- [ ] Installed NISE: `cargo install --path .` or downloaded release binary
- [ ] Connected Nitrokey and confirmed OS recognizes it
- [ ] **Changed admin key**: `nise --set-admin-key`
- [ ] **Documented admin key** in password manager or secure backup
- [ ] **Changed PIN**: `nise --set-pin`
- [ ] **Documented PIN** securely
- [ ] **Changed PUK**: `nise --set-puk`
- [ ] **Documented PUK** securely (separate from device)
- [ ] **Generated encryption key**: `nise -i -s 85`
- [ ] **Saved public key string** (starts with `nise1:`) somewhere accessible
- [ ] **Tested encryption**: Created test file and encrypted it
- [ ] **Tested decryption**: Verified you can decrypt the test file
- [ ] **Secured backup** of all credentials in safe location

---

## Additional Resources

- [Nitrokey 3 Documentation](https://docs.nitrokey.com/nitrokey3/)
- [PIV Standard Overview](https://csrc.nist.gov/projects/piv)
- [NISE README](./README.md) - Usage examples and basic information

---

## Emergency Contact

If you suspect your Nitrokey has been compromised:

1. **Stop using it immediately**
2. **Assume all encrypted data is compromised**
3. **Change any credentials that may have been protected by the device**
4. **Factory reset the device** if you plan to reuse it
5. **Re-encrypt sensitive data** with a new, secured device

---

**Remember**: Hardware security tokens like Nitrokey are only as secure as the credentials protecting them. Take 5 minutes now to secure your device properly, or risk losing everything later.
