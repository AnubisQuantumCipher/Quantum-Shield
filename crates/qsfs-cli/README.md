# qsfs

[![Crates.io](https://img.shields.io/crates/v/qsfs)](https://crates.io/crates/qsfs)
[![Documentation](https://docs.rs/qsfs/badge.svg)](https://docs.rs/qsfs)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green)](../../LICENSE-MIT)

**Quantum-Shield File System (QSFS) CLI - Post-quantum file encryption**

A command-line tool for quantum-resistant file encryption using NIST-standardized post-quantum cryptography with ML-KEM-1024 key encapsulation and ML-DSA-87 digital signatures.

## Installation

Install from crates.io:

```bash
cargo install qsfs
```

Or install with specific features:

```bash
cargo install qsfs --features "pq,gcm-siv"
```

## Quick Start

### Generate Keys

```bash
# Generate ML-KEM-1024 keypair
qsfs mlkem-keygen

# Generate X25519 keypair (for hybrid mode)
qsfs x25519-keygen

# Generate ML-DSA-87 signer keypair
qsfs signer-keygen
```

### Encrypt Files

```bash
# Basic encryption with digital signature
qsfs encrypt \
  --input document.pdf \
  --output document.qsfs \
  --recipient-pk mlkem1024.pk \
  --recipient-x25519-pk x25519.pk

# Multi-recipient encryption
qsfs encrypt \
  --input secrets.zip \
  --output secrets.qsfs \
  --recipient-pk alice.pk \
  --recipient-pk bob.pk \
  --recipient-x25519-pk alice-x25519.pk \
  --recipient-x25519-pk bob-x25519.pk
```

### Decrypt Files

```bash
# Decrypt with signature verification
qsfs decrypt \
  --input document.qsfs \
  --output document.pdf \
  --mlkem-sk mlkem1024.sk \
  --x25519-sk x25519.sk
```

### Trust Management

```bash
# List trusted signers
qsfs trust list

# Add a signer to trust store
qsfs trust add signer.mldsa87.pk --note "Alice's signing key"

# Remove a signer
qsfs trust remove a1b2c3d4e5f6...
```

## Features

### 🔐 Quantum-Resistant Security
- **ML-KEM-1024**: Post-quantum key encapsulation (NIST FIPS 203)
- **ML-DSA-87**: Post-quantum digital signatures (NIST FIPS 204)
- **AES-256-GCM/GCM-SIV**: Authenticated encryption
- **CNSA 2.0 Compliant**: NSA-approved algorithms

### 🛡️ Security Features
- **Default-on signatures**: All files signed with ML-DSA-87
- **Trust store management**: Comprehensive signer verification
- **Memory safety**: Automatic zeroization and secure handling
- **Atomic operations**: Crash-safe file operations
- **Side-channel protection**: Constant-time operations

### ⚡ Performance
- **Streaming encryption**: Handle files of any size
- **Minimal overhead**: ~11ms signature overhead regardless of file size
- **Optimized primitives**: Hardware acceleration when available

## Command Reference

### Key Generation
- `qsfs mlkem-keygen` - Generate ML-KEM-1024 keypair
- `qsfs x25519-keygen` - Generate X25519 keypair
- `qsfs signer-keygen` - Generate ML-DSA-87 signer keypair

### File Operations
- `qsfs encrypt` - Encrypt files with post-quantum cryptography
- `qsfs decrypt` - Decrypt and verify files
- `qsfs inspect` - Examine file headers and metadata

### Trust Management
- `qsfs trust list` - List trusted signers
- `qsfs trust add` - Add signer to trust store
- `qsfs trust remove` - Remove signer from trust store

## Security Profiles

### Maximum Security
```bash
qsfs encrypt \
  --input classified.zip \
  --output classified.qsfs \
  --recipient-pk recipient.pk \
  --recipient-x25519-pk recipient-x25519.pk \
  --signer-key custom-signer.mldsa87 \
  --chunk 65536
```

### Development Mode
```bash
# Trust any valid signature (development only)
qsfs decrypt \
  --input test-file.qsfs \
  --output test-file.txt \
  --mlkem-sk test.sk \
  --x25519-sk test-x25519.sk \
  --trust-any-signer
```

## File Format

QSFS creates `.qsfs` files with the following structure:

- **Header**: Contains metadata, recipient information, and ML-DSA-87 signature
- **Encrypted Data**: AES-256-GCM encrypted file chunks
- **Integrity**: BLAKE3 hash and AEAD authentication tags

## Platform Support

- ✅ Linux (x86_64, ARM64)
- ✅ macOS (Intel, Apple Silicon)
- ✅ Windows (x64)
- ✅ FreeBSD (experimental)

## Examples

### Secure Backup
```bash
#!/bin/bash
qsfs encrypt \
  --input "$HOME/Documents" \
  --output "backup-$(date +%Y%m%d).qsfs" \
  --recipient-pk backup-server.pk \
  --recipient-x25519-pk backup-server-x25519.pk
```

### Multi-User Sharing
```bash
# Encrypt for team members
qsfs encrypt \
  --input project-files.tar.gz \
  --output project.qsfs \
  --recipient-pk alice.pk \
  --recipient-pk bob.pk \
  --recipient-pk charlie.pk \
  --recipient-x25519-pk alice-x25519.pk \
  --recipient-x25519-pk bob-x25519.pk \
  --recipient-x25519-pk charlie-x25519.pk
```

## License

This project is dual-licensed under MIT OR Apache-2.0.

## Security

For security vulnerabilities, please email: security@quantum-shield.dev

**Do not create public issues for security vulnerabilities.**
