# Quantum-Shield Crates.io Publication Guide

This guide provides step-by-step instructions for publishing the Quantum-Shield File System (QSFS) to crates.io and setting up automated publishing via GitHub Actions.

## 📋 Pre-Publication Checklist

### 1. Workspace Structure
The project is now configured as a proper Rust workspace with the following crates:

- **`qsfs-core`** - Core cryptographic library (publish first)
- **`qsfs`** - CLI application (publish last)

### 2. Metadata Configuration
All crates now inherit metadata from the workspace:

```toml
[workspace.package]
version = "0.1.0"
license = "MIT OR Apache-2.0"
edition = "2021"
rust-version = "1.75"
homepage = "https://github.com/AnubisQuantumCipher/quantum-shield"
repository = "https://github.com/AnubisQuantumCipher/quantum-shield"
categories = ["cryptography", "command-line-utilities"]
keywords = ["cryptography", "post-quantum", "aead", "ml-kem", "ml-dsa"]
authors = ["AnubisQuantumCipher"]
```

### 3. Inter-Crate Dependencies
The CLI crate properly references the core crate with both version and path:

```toml
qsfs-core = { version = "0.1.0", path = "../qsfs-core", default-features = false }
```

## 🚀 Manual Publication (First Time)

### Step 1: Get crates.io API Token

1. Sign into [crates.io](https://crates.io) with your GitHub account
2. Verify your email address
3. Go to Account Settings → API Tokens
4. Create a new token with appropriate permissions
5. Save the token securely

### Step 2: Login to Cargo

```bash
cargo login <YOUR_CRATES_IO_TOKEN>
```

### Step 3: Publish in Dependency Order

**Important**: Publish the core library first, then wait for the index to update before publishing the CLI.

```bash
# 1. Publish core library
cargo publish -p qsfs-core

# 2. Wait 60-120 seconds for crates.io index update
sleep 60

# 3. Publish CLI application
cargo publish -p qsfs
```

### Step 4: Verify Installation

```bash
# Test installation from crates.io
cargo install qsfs
qsfs --version
qsfs --help
```

## 🔄 Automated Publishing Setup

### Step 1: GitHub Repository Setup

1. Push your code to the GitHub repository: `https://github.com/AnubisQuantumCipher/quantum-shield`
2. Ensure the repository is public (required for crates.io)

### Step 2: Configure GitHub Secrets

Add the following secrets to your GitHub repository (Settings → Secrets and variables → Actions):

- `CARGO_REGISTRY_TOKEN`: Your crates.io API token

### Step 3: Enable Trusted Publishing (Recommended)

After the first manual publish, enable Trusted Publishing on crates.io:

1. Go to crates.io → Your Crate → Settings → Trusted publishing
2. Add your GitHub repository as a trusted publisher
3. Configure the OIDC subject for the release workflow

### Step 4: Create Releases

Once set up, create releases by pushing tags:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This will trigger the automated release workflow.

## 📁 Files Created/Modified

### Workspace Configuration
- `Cargo.toml` - Updated with workspace metadata
- `crates/qsfs-core/Cargo.toml` - Updated with crates.io metadata
- `crates/qsfs-cli/Cargo.toml` - Updated with crates.io metadata

### Documentation
- `crates/qsfs-core/README.md` - Per-crate documentation
- `crates/qsfs-cli/README.md` - CLI-specific documentation

### GitHub Actions
- `.github/workflows/ci.yml` - Continuous integration
- `.github/workflows/release.yml` - Automated publishing

### License Files
- `LICENSE-MIT` - MIT license (already exists)
- `LICENSE-APACHE` - Apache 2.0 license (already exists)

## 🔧 Quality Assurance

### Pre-Publish Validation

Run these commands before publishing:

```bash
# Format code
cargo fmt --all -- --check

# Run lints
cargo clippy --all-features --workspace -- -D warnings

# Run tests
cargo test --all-features --workspace

# Dry run packaging
cargo package -p qsfs-core --no-verify
cargo package -p qsfs --no-verify
```

### Security Audit

```bash
# Install cargo-audit
cargo install cargo-audit

# Run security audit
cargo audit
```

## 📊 Publication Order

**Critical**: Always publish in this order to avoid dependency resolution issues:

1. **qsfs-core** (library crate) - Contains core cryptographic functionality
2. **Wait 60+ seconds** - Allow crates.io index to update
3. **qsfs** (binary crate) - CLI application that depends on qsfs-core

## 🛠️ Troubleshooting

### Common Issues

1. **"no matching package named `qsfs-core` found"**
   - Solution: Publish qsfs-core first and wait for index update

2. **"failed to verify package"**
   - Solution: Use `--no-verify` flag for initial publish

3. **"crate name already exists"**
   - Solution: Choose different crate names or contact crates.io support

### Version Management

- Keep all crates on the same version
- Bump versions together using workspace inheritance
- Use semantic versioning (SemVer)

## 🎯 Next Steps

1. **Manual Publish**: Follow the manual publication steps above
2. **Test Installation**: Verify `cargo install qsfs` works correctly
3. **Setup Automation**: Configure GitHub Actions for future releases
4. **Documentation**: Ensure docs.rs builds correctly with all features
5. **Community**: Consider adding CONTRIBUTING.md and CODE_OF_CONDUCT.md

## 📞 Support

- **Crates.io Issues**: Contact crates.io support
- **GitHub Issues**: Use the repository issue tracker
- **Security**: Email sic.tau@proton.me

---

**Ready to publish!** 🚀

The workspace is now properly configured for crates.io publication with all necessary metadata, documentation, and automation in place.
