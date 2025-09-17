#!/bin/bash

# Quantum-Shield GitHub Repository Setup Script
# This script helps set up the GitHub repository for crates.io publication

set -e

echo "🛡️ Quantum-Shield GitHub Setup"
echo "==============================="

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "Initializing git repository..."
    git init
    git branch -M main
fi

# Add all files
echo "Adding files to git..."
git add .

# Create initial commit if needed
if ! git rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "Creating initial commit..."
    git commit -m "Initial commit: Quantum-Shield File System v0.1.0

- Post-quantum file encryption with ML-KEM-1024
- Digital signatures with ML-DSA-87
- Streaming AEAD with AES-256-GCM/GCM-SIV
- Memory-safe cryptographic implementation
- CLI and library crates ready for crates.io"
fi

# Check if remote exists
if ! git remote get-url origin >/dev/null 2>&1; then
    echo "Adding GitHub remote..."
    git remote add origin https://github.com/AnubisQuantumCipher/quantum-shield.git
fi

echo ""
echo "✅ Git repository configured!"
echo ""
echo "Next steps:"
echo "1. Push to GitHub:"
echo "   git push -u origin main"
echo ""
echo "2. Set up GitHub secrets:"
echo "   - Go to: https://github.com/AnubisQuantumCipher/quantum-shield/settings/secrets/actions"
echo "   - Add secret: CARGO_REGISTRY_TOKEN (your crates.io API token)"
echo ""
echo "3. Publish to crates.io:"
echo "   cargo login <your-token>"
echo "   cargo publish -p qsfs-core"
echo "   sleep 60"
echo "   cargo publish -p qsfs"
echo ""
echo "4. Create first release:"
echo "   git tag v0.1.0"
echo "   git push origin v0.1.0"
echo ""
echo "📖 See CRATES_IO_GUIDE.md for detailed instructions"
