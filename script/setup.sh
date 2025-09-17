#!/usr/bin/env bash
set -euo pipefail

echo "==> QSFS one-time setup for this user"
echo "    - Generates ML-DSA-87 signer, ML-KEM-1024 keypair, and X25519 keypair"

export PATH="$HOME/.cargo/bin:$PATH"
command -v qsfs >/dev/null 2>&1 || { echo "qsfs not found; run script/install.sh first"; exit 1; }

QSFS_DIR="$HOME/.qsfs"
mkdir -p "$QSFS_DIR"

echo "==> Signer (ML-DSA-87)"
if [ -f "$QSFS_DIR/signer.mldsa87" ]; then
  echo "    signer exists: $QSFS_DIR/signer.mldsa87"
else
  qsfs signer-keygen || true
fi

echo "==> X25519 (hybrid)"
if [ -f "$QSFS_DIR/x25519.pk" ] && [ -f "$QSFS_DIR/x25519.sk" ]; then
  echo "    x25519 keys exist"
else
  qsfs x25519-keygen --outdir "$QSFS_DIR"
fi

echo "==> ML-KEM-1024 (recipient KEM keys)"
if [ -f "$QSFS_DIR/mlkem1024.pk" ] && [ -f "$QSFS_DIR/mlkem1024.sk" ]; then
  echo "    mlkem keys exist"
else
  qsfs-keygen
  # Move to ~/.qsfs if generated in $HOME
  for f in "$HOME/mlkem1024.pk" "$HOME/mlkem1024.sk"; do
    if [ -f "$f" ]; then mv -n "$f" "$QSFS_DIR/"; fi
  done
  # Lock down secret permissions
  if [ -f "$QSFS_DIR/mlkem1024.sk" ]; then chmod 600 "$QSFS_DIR/mlkem1024.sk" || true; fi
fi

echo "==> Trust store"
if [ -f "$QSFS_DIR/trustdb" ]; then
  echo "    trustdb exists"
else
  # signer-keygen (default path) already self-adds to trust store
  :
fi

echo "\nReady. Quick usage:"
echo "  qsfs encrypt --input /path/file --output /path/file.qsfs \\\n+      --recipient-pk $QSFS_DIR/mlkem1024.pk \\\n+      --recipient-x25519-pk $QSFS_DIR/x25519.pk"
echo "  qsfs decrypt --input /path/file.qsfs --output /path/file.dec \\\n+      --mlkem-sk $QSFS_DIR/mlkem1024.sk --x25519-sk $QSFS_DIR/x25519.sk"

