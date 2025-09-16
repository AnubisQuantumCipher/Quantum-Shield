# Installation Guide for Quantum Shield

This guide provides step-by-step instructions to install and build the `quantum-shield` project.

## Prerequisites

Ensure you have `git` installed on your system.

## 1. Install Rust and Cargo

First, install Rust and Cargo using `rustup`:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Verify the installation:

```bash
rustc --version
cargo --version
```

## 2. Clone the Repository

Clone the `quantum-shield` repository:

```bash
git clone https://github.com/AnubisQuantumCipher/quantum-shield.git
cd quantum-shield
```

## 3. Install Build Dependencies

Install `build-essential` for the C compiler:

```bash
sudo apt-get update
sudo apt-get install -y build-essential
```

## 4. Build the Project

Build the project with enhanced security features:

```bash
cargo build --release --features "pq,gcm-siv"
```

## 5. Install System-Wide

Install the `qsfs` and `qsfs-keygen` executables system-wide. The CLI forwards features to the core crate, so you can enable them directly during install:

```bash
cargo install --path crates/qsfs-cli --features "pq,gcm-siv"
```

## 6. Verify Installation

Verify that `qsfs` and `qsfs-keygen` are installed and accessible:

```bash
qsfs --version
qsfs-keygen
```

This will output the version of `qsfs` and generate key files for `qsfs-keygen`.

Note: Feature forwarding (e.g., `--features "pq,gcm-siv"`) is available in the CLI starting from the `feat/cli-feature-forwarding` update.
