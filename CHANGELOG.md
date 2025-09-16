# Changelog

All notable changes to Quantum-Shield will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enhanced documentation and examples
- Improved error messages and user experience
- Additional test coverage for edge cases

### Changed
- Performance optimizations for large file processing
- Updated dependencies to latest stable versions

### Security
- Regular security audits and dependency updates

## [2.1.0] - 2024-09-15

### Added
- **Per-file KDF salt**: New files include a 32-byte public `kdf_salt` in the header for enhanced key separation
- **Improved AAD binding**: Enhanced Authenticated Additional Data (AAD) structure for better security
- **AES-256-GCM-SIV support**: Misuse-resistant AEAD for streaming encryption (optional feature)
- **Enhanced inspection**: `qsfs inspect` command now shows AEAD suite, KDF salt status, and detailed cryptographic information
- **Backward compatibility**: Automatic detection and support for v2.0 files without KDF salt

### Changed
- **Default AEAD**: AES-256-GCM-SIV for new installations (legacy AES-256-GCM available via `--features gcm`)
- **AAD structure**: Updated from v2.0 to v2.1 format with additional security bindings
- **KDF implementation**: Enhanced key derivation with per-file salts for better key separation

### Security
- **Hardened key separation**: Per-file KDF salts prevent key reuse across different files
- **Enhanced AAD binding**: Stronger cryptographic binding of metadata to encrypted content
- **Improved domain separation**: Better isolation between different cryptographic contexts

### Technical
- **Crypto migration**: Seamless upgrade path from v2.0 to v2.1 with maintained compatibility
- **Test vectors**: Updated Known Answer Tests (KATs) and verification tools
- **Documentation**: Comprehensive crypto specification updates in `docs/CRYPTO-SPEC-v2.md`

## [2.0.0] - 2024-08-01

### Added
- **🆕 ML-DSA-87 Digital Signatures**: Post-quantum digital signatures for file authenticity
  - Default-on signing for all encrypted files
  - Detached signatures with canonical header serialization
  - Mandatory signature verification before decryption
  - Non-repudiation and cryptographic proof of origin
- **🆕 Trust Store Management**: Comprehensive signer verification system
  - `qsfs trust` subcommands for signer management
  - Trusted signer database with metadata
  - Automatic signer key provisioning
  - Flexible trust policies for different use cases
- **🆕 Enhanced CLI Interface**:
  - New `signer-keygen` command for ML-DSA-87 key generation
  - Enhanced `encrypt`/`decrypt` commands with signature options
  - Better error messages and security warnings
  - Comprehensive help and usage examples
- **🆕 Security Profiles**:
  - Maximum security profile with custom signers
  - Development profile with relaxed trust requirements
  - Legacy support for unsigned files (not recommended)
- **🆕 File Format v2.0**:
  - Enhanced QSFS container with signature metadata
  - Improved header structure with cryptographic binding
  - Backward compatibility with v1.x files

### Changed
- **Breaking**: Default behavior now includes ML-DSA-87 signatures
- **Breaking**: Signature verification required by default for decryption
- **Enhanced**: Improved error handling and user feedback
- **Enhanced**: Better performance for large file operations
- **Enhanced**: More comprehensive test coverage including signature workflows

### Security
- **Added**: Non-repudiation through cryptographic signatures
- **Added**: File authenticity verification with trust store
- **Added**: Enhanced tamper detection with signature validation
- **Improved**: Stronger cryptographic binding of metadata
- **Improved**: Better protection against implementation attacks

### Documentation
- **Added**: Comprehensive signature implementation guide
- **Added**: Trust store management documentation
- **Added**: Security architecture documentation
- **Updated**: API reference with signature functions
- **Updated**: Migration guide for v2.0 upgrade

### Performance
- **Improved**: Signature operations with constant-time implementation
- **Improved**: Memory efficiency for large file processing
- **Improved**: Reduced overhead for multi-recipient scenarios

## [1.2.0] - 2024-06-15

### Added
- **Multi-recipient encryption**: Support for encrypting to multiple recipients
- **Streaming AEAD**: Efficient processing of large files with chunked encryption
- **Enhanced key derivation**: HKDF-SHA3-384 with proper domain separation
- **Memory safety improvements**: Automatic zeroization of sensitive data
- **Performance optimizations**: Faster encryption/decryption for large files

### Changed
- **Improved CLI**: Better command-line interface with more options
- **Enhanced error handling**: More descriptive error messages
- **Updated dependencies**: Latest versions of cryptographic libraries

### Security
- **Added**: Side-channel protection with constant-time operations
- **Added**: Memory locking for cryptographic operations
- **Improved**: Input validation and sanitization
- **Improved**: Secure random number generation

### Fixed
- **Memory leaks**: Fixed potential memory leaks in error paths
- **Edge cases**: Better handling of edge cases in file processing
- **Platform compatibility**: Improved compatibility across different platforms

## [1.1.0] - 2024-04-20

### Added
- **X25519 key exchange**: Additional key exchange mechanism for hybrid security
- **Cascade encryption**: Optional cascaded encryption for enhanced security
- **Nonce misuse resistance**: AES-GCM-SIV support for nonce misuse scenarios
- **Enhanced logging**: Comprehensive logging for audit and debugging
- **Platform support**: Extended platform compatibility

### Changed
- **Improved performance**: Optimized cryptographic operations
- **Better documentation**: Enhanced user and developer documentation
- **Updated build system**: Improved build configuration and features

### Security
- **Added**: Hybrid key exchange with both ML-KEM and X25519
- **Added**: Protection against nonce misuse attacks
- **Improved**: Enhanced entropy collection for key generation

### Fixed
- **Build issues**: Fixed compilation issues on some platforms
- **Memory usage**: Reduced memory footprint for large operations
- **Error handling**: Improved error propagation and handling

## [1.0.0] - 2024-02-01

### Added
- **Initial release**: First stable version of Quantum-Shield
- **ML-KEM-1024**: NIST-standardized post-quantum key encapsulation
- **AES-256-GCM**: Authenticated encryption with additional data
- **BLAKE3 hashing**: High-performance cryptographic hashing
- **HKDF key derivation**: Secure key derivation function
- **CLI interface**: Command-line tool for encryption and decryption
- **Library API**: Rust library for integration into other applications

### Security
- **Quantum resistance**: Protection against quantum computer attacks
- **Forward secrecy**: Compromise of long-term keys doesn't affect past sessions
- **Integrity protection**: Cryptographic integrity verification
- **Memory safety**: Rust's memory safety guarantees

### Features
- **File encryption**: Secure encryption of files and directories
- **Key management**: Secure key generation and storage
- **Cross-platform**: Support for Linux, macOS, and Windows
- **High performance**: Optimized for speed and efficiency

## [0.9.0] - 2024-01-15 (Beta)

### Added
- **Beta release**: Feature-complete beta version
- **Comprehensive testing**: Extensive test suite with known answer tests
- **Documentation**: Complete user and developer documentation
- **Security audit**: Initial security review and testing

### Changed
- **API stabilization**: Finalized API for 1.0 release
- **Performance tuning**: Optimized performance for production use
- **Error handling**: Improved error messages and handling

### Security
- **Security review**: Comprehensive security analysis
- **Vulnerability testing**: Penetration testing and vulnerability assessment
- **Cryptographic validation**: Validation against test vectors

## [0.8.0] - 2023-12-01 (Alpha)

### Added
- **Alpha release**: Initial public release
- **Core functionality**: Basic encryption and decryption
- **Post-quantum crypto**: ML-KEM implementation
- **Basic CLI**: Command-line interface for testing

### Security
- **Initial implementation**: First implementation of post-quantum algorithms
- **Basic security**: Fundamental security properties

---

## Security Advisories

### SA-2024-001 - Information Disclosure in Error Messages (Low)
- **Affected Versions**: 1.0.0 - 1.1.0
- **Fixed in**: 1.1.1
- **Description**: Error messages could potentially leak information about file structure
- **Mitigation**: Upgrade to version 1.1.1 or later

### SA-2024-002 - Memory Disclosure in Debug Builds (Medium)
- **Affected Versions**: 0.9.0 - 1.0.0 (debug builds only)
- **Fixed in**: 1.0.1
- **Description**: Debug builds could leave sensitive data in memory
- **Mitigation**: Use release builds in production, upgrade to 1.0.1 or later

---

## Migration Guide

### Upgrading to v2.1.0

**Automatic Migration**: Files encrypted with v2.0 can be decrypted with v2.1 without any changes.

**New Features**: New files encrypted with v2.1 will include enhanced security features and require v2.1 or later to decrypt.

**Recommendations**:
- Update to v2.1.0 for enhanced security
- Re-encrypt sensitive files to benefit from new security features
- Review and update trust store configurations

### Upgrading to v2.0.0

**Breaking Changes**: 
- Default behavior now includes ML-DSA-87 signatures
- Signature verification required by default

**Migration Steps**:
1. Update to v2.0.0
2. Generate ML-DSA-87 signer keys: `qsfs signer-keygen`
3. Set up trust store: `qsfs trust add signer.mldsa87.pk`
4. Re-encrypt files to include signatures
5. Update scripts and automation

**Backward Compatibility**:
- v1.x files can still be decrypted
- Use `--allow-unsigned` flag for legacy files
- Gradual migration recommended

### Upgrading to v1.0.0

**Stable API**: v1.0.0 introduced the stable API that is maintained through v1.x releases.

**Migration from Beta**:
- Update configuration file format
- Regenerate keys with stable key format
- Update integration code to use stable API

---

## Support and Compatibility

### Version Support Policy

- **Current Major Version**: Full support with security updates
- **Previous Major Version**: Security updates for 12 months
- **Older Versions**: No support, upgrade recommended

### Platform Compatibility

| Platform | v1.x | v2.0 | v2.1 | Notes |
|----------|------|------|------|-------|
| Linux x86_64 | ✅ | ✅ | ✅ | Primary platform |
| macOS ARM64 | ✅ | ✅ | ✅ | Apple Silicon |
| Windows x64 | ✅ | ✅ | ✅ | MSVC/GNU |
| Linux ARM64 | ✅ | ✅ | ✅ | Raspberry Pi 4+ |
| FreeBSD | 🟡 | 🟡 | 🟡 | Community support |

### Rust Version Compatibility

- **Minimum Rust Version**: 1.75.0
- **Recommended**: Latest stable Rust
- **MSRV Policy**: Updated with major releases

---

**🛡️ For the complete version history and detailed release notes, visit our [GitHub Releases](https://github.com/AnubisQuantumCipher/quantum-shield/releases) page.**
