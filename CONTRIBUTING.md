# Contributing to Quantum-Shield

Thank you for your interest in contributing to Quantum-Shield! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Guidelines](#contributing-guidelines)
- [Security Guidelines](#security-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)

## Code of Conduct

This project adheres to a code of conduct that promotes a welcoming and inclusive environment. By participating, you are expected to uphold this code.

### Our Standards

- **Be respectful** and inclusive in all interactions
- **Be constructive** in feedback and discussions
- **Focus on the technical merit** of contributions
- **Respect different viewpoints** and experiences
- **Show empathy** towards other community members

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Rust 1.75+** installed via [rustup](https://rustup.rs/)
- **Git** for version control
- **Build tools** (`build-essential` on Ubuntu/Debian)
- **Basic understanding** of cryptography concepts
- **Familiarity** with Rust programming language

### Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/quantum-shield.git
   cd quantum-shield
   ```

3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/AnubisQuantumCipher/quantum-shield.git
   ```

4. **Install dependencies and build**:
   ```bash
   cargo build --release --features "pq,gcm-siv"
   ```

5. **Run tests** to ensure everything works:
   ```bash
   cargo test --all-features
   ```

## Contributing Guidelines

### Types of Contributions

We welcome various types of contributions:

- **Bug fixes** and security patches
- **Feature implementations** (discuss first in issues)
- **Documentation improvements**
- **Performance optimizations**
- **Test coverage improvements**
- **Code quality enhancements**

### Coding Standards

#### Rust Code Style

- **Follow Rust conventions** and idioms
- **Use `cargo fmt`** for consistent formatting
- **Run `cargo clippy`** and address all warnings
- **Write comprehensive documentation** for public APIs
- **Include unit tests** for new functionality
- **Maintain backwards compatibility** when possible

#### Security Requirements

- **No unsafe code** without explicit justification and review
- **Constant-time operations** for cryptographic functions
- **Memory safety** with automatic zeroization
- **Input validation** for all external data
- **Error handling** that doesn't leak sensitive information

#### Code Quality

```bash
# Format code
cargo fmt

# Check for common mistakes
cargo clippy -- -D warnings

# Run security audit
cargo audit

# Check test coverage
cargo tarpaulin --out Html
```

### Cryptographic Guidelines

#### Algorithm Implementation

- **Use only NIST-approved** post-quantum algorithms
- **Follow reference implementations** from PQClean
- **Implement constant-time operations** for sensitive data
- **Include comprehensive test vectors**
- **Document security assumptions** clearly

#### Key Management

- **Secure key generation** with proper entropy
- **Automatic memory zeroization** for private keys
- **Clear key lifecycle management**
- **Proper key serialization** formats

## Security Guidelines

### Security-First Development

Security is our top priority. All contributions must adhere to strict security standards:

#### Memory Safety

- **Automatic zeroization** of sensitive data
- **No buffer overflows** or memory leaks
- **Secure memory allocation** for cryptographic operations
- **Protection against** side-channel attacks

#### Cryptographic Security

- **Quantum-resistant algorithms** only
- **Proper random number generation**
- **Secure key derivation** functions
- **Authenticated encryption** with additional data

#### Implementation Security

- **Input validation** for all external data
- **Fail-closed security** model
- **Comprehensive error handling**
- **No information leakage** through timing or errors

### Security Review Process

All cryptographic changes require:

1. **Technical review** by maintainers
2. **Security analysis** of the implementation
3. **Test vector validation** against known answers
4. **Performance impact** assessment
5. **Documentation** of security properties

## Testing

### Test Requirements

All contributions must include appropriate tests:

#### Unit Tests

- **Test all public APIs** thoroughly
- **Include edge cases** and error conditions
- **Test cryptographic operations** with known vectors
- **Verify memory safety** and cleanup

#### Integration Tests

- **End-to-end encryption/decryption** workflows
- **Multi-recipient scenarios**
- **Signature verification** processes
- **Trust store management**

#### Security Tests

- **Known Answer Tests (KATs)** for cryptographic functions
- **Negative tests** for invalid inputs
- **Memory safety** validation
- **Side-channel resistance** testing

### Running Tests

```bash
# Run all tests
cargo test --all-features

# Run specific test suite
cargo test signature_workflow --release

# Run with coverage
cargo tarpaulin --out Html

# Run security tests
cargo test security --release
```

## Documentation

### Documentation Standards

- **Clear and comprehensive** API documentation
- **Usage examples** for all public functions
- **Security considerations** for cryptographic operations
- **Performance characteristics** and benchmarks
- **Migration guides** for breaking changes

### Documentation Types

#### Code Documentation

- **Rustdoc comments** for all public items
- **Examples** in documentation comments
- **Links to relevant** specifications and standards
- **Security warnings** where appropriate

#### User Documentation

- **Installation guides** for different platforms
- **Usage tutorials** with practical examples
- **Security best practices**
- **Troubleshooting guides**

#### Developer Documentation

- **Architecture overview**
- **Cryptographic specifications**
- **Build and deployment** instructions
- **Contributing guidelines**

## Pull Request Process

### Before Submitting

1. **Create an issue** to discuss significant changes
2. **Fork the repository** and create a feature branch
3. **Write comprehensive tests** for your changes
4. **Update documentation** as needed
5. **Run the full test suite** locally

### Pull Request Guidelines

#### Title and Description

- **Clear, descriptive title** summarizing the change
- **Detailed description** of what and why
- **Reference related issues** using keywords
- **List breaking changes** if any

#### Code Review Process

1. **Automated checks** must pass (CI/CD)
2. **Code review** by at least one maintainer
3. **Security review** for cryptographic changes
4. **Documentation review** for user-facing changes
5. **Final approval** and merge

### Commit Guidelines

- **Atomic commits** with single logical changes
- **Clear commit messages** following conventional format
- **Sign commits** with GPG key (recommended)
- **Rebase** instead of merge commits when possible

Example commit message:
```
feat(crypto): add ML-DSA-87 signature verification

- Implement signature verification for encrypted files
- Add trust store management for signer keys
- Include comprehensive test coverage
- Update documentation with usage examples

Fixes #123
```

## Issue Reporting

### Bug Reports

When reporting bugs, please include:

- **Clear description** of the issue
- **Steps to reproduce** the problem
- **Expected vs actual** behavior
- **Environment details** (OS, Rust version, etc.)
- **Relevant logs** or error messages
- **Minimal test case** if possible

### Feature Requests

For feature requests, please provide:

- **Clear description** of the proposed feature
- **Use case** and motivation
- **Proposed implementation** approach
- **Potential impact** on existing functionality
- **Alternative solutions** considered

### Security Issues

**Do not create public issues for security vulnerabilities.**

Instead, please email: security@quantum-shield.dev

Include:
- **Detailed description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** assessment
- **Suggested mitigation** if known

## Development Workflow

### Branch Strategy

- **main**: Stable release branch
- **develop**: Integration branch for new features
- **feature/***: Feature development branches
- **hotfix/***: Critical bug fix branches
- **release/***: Release preparation branches

### Release Process

1. **Feature freeze** on develop branch
2. **Create release branch** from develop
3. **Final testing** and bug fixes
4. **Update version** numbers and changelog
5. **Merge to main** and tag release
6. **Deploy** to package registries

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Security Email**: security@quantum-shield.dev

### Getting Help

If you need help:

1. **Check existing documentation** and issues
2. **Search GitHub discussions** for similar questions
3. **Create a new discussion** with detailed information
4. **Be patient** and respectful in all interactions

## Recognition

We value all contributions to Quantum-Shield. Contributors will be:

- **Listed in CONTRIBUTORS.md** file
- **Mentioned in release notes** for significant contributions
- **Invited to join** the core team for sustained contributions

## License

By contributing to Quantum-Shield, you agree that your contributions will be licensed under the same terms as the project (MIT/Apache-2.0 dual license).

---

Thank you for contributing to Quantum-Shield! Together, we're building the future of quantum-resistant cryptography.
