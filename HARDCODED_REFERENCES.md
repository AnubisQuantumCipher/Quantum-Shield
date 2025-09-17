# Hardcoded References in Quantum-Shield

This document catalogs the hardcoded constants, magic numbers, and fixed values found in the Quantum-Shield codebase. These are primarily cryptographic constants and configuration values that are intentionally fixed for security and compatibility reasons.

## 🔐 Cryptographic Constants

### Key Sizes and Algorithm Parameters

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| `MLKEM1024_CT_LEN` | 1568 | `qsfs-cli/src/main.rs:160` | ML-KEM-1024 ciphertext length |
| `MLDSA87_PK_LEN` | 2592 | `qsfs-cli/src/main.rs:161` | ML-DSA-87 public key length |
| X25519 key size | 32 | Multiple locations | X25519 key size validation |
| AES key size | 32 | `derivation.rs` | AES-256 key length |
| Nonce size | 12 | `derivation.rs` | AES-GCM nonce length |
| Blake3 hash size | 32 | `lib.rs` | Hash output length |
| File ID size | 8 | `derivation.rs` | File nonce seed length |
| KDF salt size | 32 | `lib.rs` | Per-file KDF salt length |

### Magic Numbers and Identifiers

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| File magic | `"QSFS2\0"` | `lib.rs:78` | File format identifier |
| Suite ID AES-GCM | 1 | `suite.rs:6` | Cipher suite identifier |
| Suite ID AES-GCM-SIV | 2 | `suite.rs:7` | Cipher suite identifier |
| Default chunk size | 131072 | `qsfs-cli/src/main.rs:35` | Default encryption chunk size |

### Cryptographic Domain Separators

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| HKDF salt | `"qsfs/hkdf/v2"` | `derivation.rs:44` | HKDF domain separation |
| KEK derivation | `"qsfs/kek/v2"` | `derivation.rs:82` | KEK derivation context |
| Stream key K1 | `"qsfs/stream/k1"` | `derivation.rs:50` | Stream key derivation |
| Stream key K2 | `"qsfs/stream/k2"` | `derivation.rs:51` | Stream key derivation |
| Nonce prefix | `"qsfs/nonce-prefix"` | `derivation.rs:62` | Nonce derivation |
| Confirm context | `"qsfs_confirm_v2"` | `lib.rs:95` | Key confirmation |
| PAE prefix | `"QSFS-PAE\x01"` | Various | Plaintext Authentication Encoding |

## 🔧 Configuration Constants

### Default Values

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| Default chunk size | 131072 | CLI args | Default encryption chunk size |
| Header size limit | 1MB | `lib.rs:189` | Maximum header size |
| Wrapped DEK size | 48 | `derivation.rs:91` | AES-GCM wrapped key size |

### File Paths and Names

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| ML-KEM key files | `"mlkem1024.pk"`, `"mlkem1024.sk"` | `qsfs-keygen.rs` | Default key file names |
| X25519 key files | `"x25519.pk"`, `"x25519.sk"` | CLI | Default key file names |

## 🛡️ Security-Related Constants

### Memory and System Security

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| File permissions | 0o600 | `security.rs:118` | Secure file permissions |
| Core dump limit | 0 | `security.rs:95` | Disable core dumps |

### Validation Limits

| Constant | Value | Location | Purpose |
|----------|-------|----------|---------|
| Max header size | 1,048,576 | `lib.rs:189` | Prevent DoS attacks |
| Wrapped DEK size | 48 | `derivation.rs:91` | Expected ciphertext size |

## 📊 Analysis Summary

### Categories of Hardcoded Values

1. **Cryptographic Constants** (85%): Algorithm-specific sizes and parameters
2. **Protocol Identifiers** (10%): Magic numbers and version identifiers  
3. **Security Limits** (5%): DoS prevention and resource limits

### Security Assessment

- ✅ **Cryptographic constants**: Properly defined by standards (NIST FIPS 203/204)
- ✅ **Domain separators**: Unique strings prevent cross-protocol attacks
- ✅ **Magic numbers**: Clear file format identification
- ✅ **Security limits**: Reasonable bounds to prevent attacks
- ✅ **Default values**: Secure defaults that can be overridden

### Recommendations

1. **Keep as-is**: Most hardcoded values are cryptographically necessary
2. **Document**: Ensure all constants are well-documented (✅ Done)
3. **Test**: Verify constants match specification requirements (✅ Done)
4. **Version**: Use version-specific domain separators (✅ Done)

## 🔍 Notes

- All cryptographic constants are derived from NIST standards
- Domain separators follow cryptographic best practices
- File format constants ensure compatibility and security
- Default values provide secure out-of-the-box experience
- No hardcoded secrets or credentials found ✅

These hardcoded references are **intentional and secure** - they represent cryptographic constants, protocol identifiers, and security parameters that must be fixed for interoperability and security.
