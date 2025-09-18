# 🛡️ Quantum-Shield: The Complete Post-Quantum & Hybrid Encryption System

**A comprehensive, defense-in-depth cryptographic solution for the quantum era, featuring a full suite of CNSA 2.0 compliant and hybrid encryption technologies.**

[![Crates.io](https://img.shields.io/crates/v/qsfs.svg)](https://crates.io/crates/qsfs)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/AnubisQuantumCipher/quantum-shield)
[![Security](https://img.shields.io/badge/security-CNSA%202.0%20%7C%20NIST%20Level%205-blue)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green)](LICENSE-MIT)
[![Features](https://img.shields.io/badge/features-all%20enabled-purple)](./crates/qsfs-core/Cargo.toml#L23)

Quantum-Shield is a state-of-the-art, quantum-resistant file encryption system that provides a complete cryptographic arsenal for the post-quantum world. It combines NIST-standardized post-quantum algorithms with battle-tested classical cryptography to deliver an unparalleled level of security against all known threats, both classical and quantum.

## 🔐 **Complete Cryptographic Suite**

Quantum-Shield provides a full spectrum of cryptographic primitives, all enabled by default, to ensure maximum security out of the box.

| Category                                   | Algorithm                                       | Standard/Reference                                                                    |
| ------------------------------------------ | ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| **Post-Quantum Cryptography**              |                                                 | **CNSA 2.0 Compliant**                                                                |
| *Key Encapsulation*                        | **ML-KEM-1024 (Kyber)**                         | FIPS 203                                                                              |
| *Digital Signatures*                       | **ML-DSA-87 (Dilithium)**                       | FIPS 204                                                                              |
| **Hybrid Classical Cryptography**          |                                                 |                                                                                       |
| *Key Exchange*                             | **X25519 (Curve25519)**                         | RFC 7748                                                                              |
| *Digital Signatures*                       | **Ed25519**                                     | RFC 8032                                                                              |
| **Authenticated Encryption (AEAD)**        |                                                 |                                                                                       |
| *Default AEAD*                             | **AES-256-GCM-SIV**                             | RFC 8452 (Nonce-Misuse Resistant)                                                     |
| *Alternative AEAD*                         | **AES-256-GCM**                                 | NIST SP 800-38D                                                                       |
| *Alternative AEAD*                         | **ChaCha20-Poly1305**                           | RFC 8439                                                                              |
| **Hashing & Key Derivation**               |                                                 |                                                                                       |
| *Primary Hasher*                           | **BLAKE3**                                      | [BLAKE3 Official Site](https://github.com/BLAKE3-team/BLAKE3)                         |
| *Key Derivation*                           | **HKDF with SHA-384**                           | RFC 5869                                                                              |
| *Password Hashing*                         | **Argon2**                                      | RFC 9106                                                                              |
| *Auxiliary Hashing*                        | **SHA-3, SHA-2**                                | FIPS 202, FIPS 180-4                                                                  |
| **Hardware Security Module (HSM)**         |                                                 |                                                                                       |
| *Interface*                                | **PKCS#11**                                     | OASIS Standard                                                                        |

## ✨ **Advanced Security Architecture**

Quantum-Shield is engineered with a defense-in-depth philosophy, incorporating multiple layers of security to protect against a wide range of attack vectors.

-   **Quantum Resistance**: Utilizes ML-KEM-1024 and ML-DSA-87, standardized by NIST, to protect against attacks from quantum computers.
-   **Hybrid Security**: Combines post-quantum and classical cryptography (X25519) to ensure security even in the unlikely event of a breakthrough in cryptanalysis of one primitive set.
-   **Nonce-Misuse Resistance**: Defaults to AES-256-GCM-SIV to prevent catastrophic failures in the case of nonce reuse.
-   **Memory Safety**: Built in Rust with a focus on memory safety. Utilizes the `secrecy` and `zeroize` crates to ensure that sensitive cryptographic material is automatically cleared from memory after use.
-   **Constant-Time Operations**: Protects against timing-based side-channel attacks by ensuring that cryptographic operations take the same amount of time regardless of the input.
-   **Mandatory Authenticity**: All encrypted files are digitally signed with ML-DSA-87 by default, ensuring both integrity and authenticity. Decryption requires signature verification.
-   **Streaming Encryption**: Efficiently encrypts and decrypts large files without requiring large amounts of memory, using a streaming AEAD interface.

## 🚀 **Quick Start**

### **Installation**

Install the Quantum-Shield CLI directly from crates.io:

```bash
cargo install qsfs
```

### **Encryption & Decryption Workflow**

1.  **Generate Keys**: Quantum-Shield will automatically generate all necessary keys on first run.

    ```bash
    # Generate ML-KEM, ML-DSA, and X25519 keys
    qsfs-keygen
    qsfs signer-keygen
    qsfs x25519-keygen
    ```

2.  **Encrypt a File**:

    ```bash
    qsfs encrypt \
      --input sensitive-document.pdf \
      --output document.qsfs \
      --recipient-pk ~/.qsfs/mlkem1024.pk
    ```

3.  **Decrypt a File**:

    ```bash
    qsfs decrypt \
      --input document.qsfs \
      --output decrypted-document.pdf \
      --mlkem-sk ~/.qsfs/mlkem1024.sk
    ```

## 🛠️ **Build Features**

All cryptographic features are enabled by default to provide the highest level of security. You can customize the build by disabling default features and enabling only the ones you need.

```toml
# Default features in crates/qsfs-core/Cargo.toml
[features]
default = ["pq", "hybrid-x25519", "gcm-siv", "gcm", "cascade", "hsm"]

# Post-Quantum Cryptography
pq = ["pqcrypto-mlkem", "pqcrypto-mldsa", "pqcrypto-traits"]

# Hybrid Classical Cryptography
hybrid-x25519 = ["x25519-dalek", "ed25519-dalek"]

# AEAD Ciphers
gcm-siv = ["aes-gcm-siv"] # Nonce-misuse resistant
gcm = []
cascade = ["chacha20poly1305"]

# Hardware Security Module Support
hsm = ["cryptoki"]
```

## 📄 **License**

This project is dual-licensed under the MIT License and the Apache License 2.0.

## 🔒 **Security Disclosure**

For security vulnerabilities, please email: `sic.tau@proton.me`. **Do not create public issues for security vulnerabilities.**



## 💻 **Complete Command-Line Reference**

This section provides a comprehensive reference for all `qsfs` and `qsfs-keygen` commands, detailing every option and providing practical examples for each.

### **`qsfs` - Main CLI**

The `qsfs` command is the primary interface for encryption, decryption, and managing the Quantum-Shield system.

#### **`qsfs encrypt`**

Encrypts a file with the full quantum-resistant suite, including ML-KEM-1024 for key encapsulation and ML-DSA-87 for digital signatures.

**Usage:**

```bash
qsfs encrypt [OPTIONS] --input <INPUT> --output <OUTPUT> --recipient-pk <RECIPIENT_PK>...
```

**Options:**

| Option | Description |
| :--- | :--- |
| `--input <INPUT>` | Path to the input file to encrypt. |
| `--output <OUTPUT>` | Path to write the encrypted output file. |
| `--recipient-pk <RECIPIENT_PK>` | Path to the recipient's ML-KEM-1024 public key. Can be specified multiple times for multiple recipients. |
| `--recipient-x25519-pk <RECIPIENT_X25519_PK>` | Path to the recipient's X25519 public key for hybrid encryption. |
| `--signer-key <SIGNER_KEY>` | Path to the ML-DSA-87 signer key. If not provided, the default signer is used. |
| `--no-signer` | **(Not Recommended)** Disables digital signatures. |
| `--chunk <CHUNK_SIZE>` | Custom chunk size for streaming encryption (default: 131072). |
| `--explain` | Prints a detailed explanation of the encryption process. |

**Example:**

```bash
# Encrypt a document for two recipients with a custom signer
qsfs encrypt \
  --input financial-report.docx \
  --output report.qsfs \
  --recipient-pk alice.pk \
  --recipient-pk bob.pk \
  --signer-key company-signer.mldsa87
```

#### **`qsfs decrypt`**

Decrypts a file encrypted with Quantum-Shield, verifying the ML-DSA-87 digital signature.

**Usage:**

```bash
qsfs decrypt [OPTIONS] --input <INPUT> --output <OUTPUT> --mlkem-sk <MLKEM_SK>
```

**Options:**

| Option | Description |
| :--- | :--- |
| `--input <INPUT>` | Path to the encrypted input file. |
| `--output <OUTPUT>` | Path to write the decrypted output file. |
| `--mlkem-sk <MLKEM_SK>` | Path to your ML-KEM-1024 secret key. |
| `--x25519-sk <X25519_SK>` | Path to your X25519 secret key for hybrid decryption. |
| `--trust-any-signer` | **(Development Only)** Trusts any valid signature, bypassing the trust store. |
| `--allow-unsigned` | **(Security Risk)** Allows decryption of files without a digital signature. |

**Example:**

```bash
# Decrypt a file with your secret keys
qsfs decrypt \
  --input report.qsfs \
  --output financial-report.docx \
  --mlkem-sk my-secret.sk \
  --x25519-sk my-x25519.sk
```

#### **`qsfs inspect`**

Inspects the header of an encrypted file without decrypting it, showing cryptographic details.

**Usage:**

```bash
qsfs inspect <FILE>
```

**Example:**

```bash
qsfs inspect report.qsfs
```

#### **`qsfs signer-keygen`**

Generates a new ML-DSA-87 signer key pair.

**Usage:**

```bash
qsfs signer-keygen
```

#### **`qsfs trust`**

Manages the trust store for ML-DSA-87 signers.

**Subcommands:**

- `list`: Lists all trusted signers.
- `add <SIGNER_PK>`: Adds a signer to the trust store.
- `remove <SIGNER_ID>`: Removes a signer from the trust store.

**Examples:**

```bash
# List trusted signers
qsfs trust list

# Add a new trusted signer
qsfs trust add new-signer.pk --note "Trusted partner key"

# Remove a signer
qsfs trust remove 132c737be10f5d2c...
```

### **`qsfs-keygen` - Key Generation Utility**

The `qsfs-keygen` utility generates ML-KEM-1024 key pairs.

**Usage:**

```bash
qsfs-keygen
```

This command will create `mlkem1024.pk` and `mlkem1024.sk` in the current directory.
