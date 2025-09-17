# Quantum Shield WASI Build and a-Shell Deployment Guide

This guide provides instructions on how to use the automated WASI build system for the Quantum Shield project and how to deploy the binaries on a-Shell for iOS.




## GitHub Actions Workflow

The repository is now configured with a GitHub Actions workflow that automatically builds and releases the `qsfs` and `qsfs-keygen` tools as both native binaries and WebAssembly (WASI) modules. The workflow is triggered on every push and pull request, and a new release is automatically created when a new tag is pushed.

You can view the workflow status and download the latest release from the [Actions tab](https://github.com/AnubisQuantumCipher/quantum-shield/actions) and the [Releases page](https://github.com/AnubisQuantumCipher/quantum-shield/releases) of the repository.




## a-Shell Deployment

To use the WASI binaries on your iPhone with a-Shell, follow these steps:

1. **Download the WASI binaries:**
   - Go to the [Releases page](https://github.com/AnubisQuantumCipher/quantum-shield/releases) of the repository.
   - From the latest release, download the `qsfs-wasm.zip` file.
   - Unzip the file to get `qsfs.wasm` and `qsfs-keygen.wasm`.

2. **Transfer the binaries to your iPhone:**
   - Use iCloud Drive, AirDrop, or any other method to transfer the `.wasm` files to the `~/Documents/bin` directory in a-Shell on your iPhone.

3. **Run the binaries in a-Shell:**
   - Open a-Shell on your iPhone.
   - You can now run the commands directly by their names:
     ```bash
     qsfs
     qsfs-keygen
     ```

4. **Generate new keys:**
   - To generate new ML-KEM-1024 and ML-DSA-87 keys, run the following command:
     ```bash
     qsfs-keygen
     ```

This will create new key files in the current directory, which you can then use with the `qsfs` tool for your quantum-safe file encryption needs.


