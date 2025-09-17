# qsfs-core

[![Crates.io](https://img.shields.io/crates/v/qsfs-core)](https://crates.io/crates/qsfs-core)
[![Documentation](https://docs.rs/qsfs-core/badge.svg)](https://docs.rs/qsfs-core)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green)](../../LICENSE-MIT)

**Core cryptographic library for Quantum-Shield File System (QSFS)**

This crate provides the core cryptographic primitives and file format implementation for QSFS, a quantum-resistant file encryption system that implements NIST-standardized post-quantum cryptography with ML-DSA-87 digital signatures.

## Features

- **Post-Quantum Cryptography**: ML-KEM-1024 (FIPS 203) for key encapsulation
- **Digital Signatures**: ML-DSA-87 (FIPS 204) for file authenticity and non-repudiation
- **Authenticated Encryption**: AES-256-GCM and AES-256-GCM-SIV support
- **Key Derivation**: HKDF-SHA3-384 with enhanced domain separation
- **Memory Safety**: Automatic zeroization and secure memory handling
- **Streaming AEAD**: Efficient processing of large files

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
qsfs-core = "0.1.0"
```

### Basic Usage

```rust
use qsfs_core::{seal, unseal, SealRequest, UnsealContext};
use tokio::fs::File;

// Encrypt a file
let request = SealRequest {
    input_path: "document.pdf",
    recipients: vec![(
        "alice".to_string(),
        ml_kem_public_key,
        x25519_public_key,
    )],
    header_sign_mldsa_sk: Some(signing_key),
    chunk_size: 131072,
    signer: Some(&signer),
};

seal(request, "document.qsfs").await?;

// Decrypt a file
let input = File::open("document.qsfs").await?;
let context = UnsealContext {
    mlkem_sk: &ml_kem_secret_key,
    x25519_sk: Some(x25519_secret_key),
    allow_unsigned: false,
    trust_any_signer: false,
};

unseal(input, "decrypted.pdf", context).await?;
```

## Security Features

### Quantum Resistance
- **ML-KEM-1024**: NIST Level 5 security against quantum attacks
- **ML-DSA-87**: NIST Level 5 post-quantum digital signatures
- **CNSA 2.0 Compliant**: Meets NSA Commercial National Security Algorithm Suite requirements

### Memory Safety
- Automatic zeroization of sensitive data
- Secure memory allocation and locking
- Constant-time operations for cryptographic primitives

### File Format Security
- Authenticated encryption with additional data (AEAD)
- Cryptographic binding of metadata and ciphertext
- Tamper detection through digital signatures
- Forward secrecy through ephemeral key exchange

## Crate Features

- `default`: Enables `pq`, `hybrid-x25519`, and `gcm-siv`
- `pq`: Post-quantum cryptography (ML-KEM, ML-DSA)
- `hybrid-x25519`: Classical X25519 hybrid mode
- `gcm-siv`: AES-256-GCM-SIV for nonce misuse resistance
- `cascade`: ChaCha20-Poly1305 cascade encryption
- `hsm`: Hardware Security Module support
- `wasm`: WebAssembly compatibility

## Architecture

The library is organized into several modules:

- **`derivation`**: Key derivation and cryptographic key management
- **`header`**: File format header parsing and serialization
- **`streaming`**: Streaming AEAD for large file processing
- **`security`**: Memory safety and system security features
- **`signer`**: Digital signature creation and verification
- **`canonical`**: Deterministic serialization for signatures

## Performance

QSFS-core is optimized for both security and performance:

- **Streaming encryption**: Process files of any size with constant memory usage
- **Optimized primitives**: Uses hardware acceleration when available
- **Minimal overhead**: Signature verification adds only ~11ms regardless of file size

## License

This project is dual-licensed under MIT OR Apache-2.0.

## Security

For security vulnerabilities, please email: sic.tau@proton.me

**Do not create public issues for security vulnerabilities.**
