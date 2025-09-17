# QSFS v2 Cryptographic Specification

This specification defines the on‑disk format, cryptographic primitives, and pre‑authenticated encoding (PAE) used by QSFS v2.

## 1. Notation and IDs
- Bytes are big‑endian unless stated otherwise.
- Constant strings are ASCII.
- Suite IDs:
  - `aes256-gcm` — AES‑256‑GCM (12‑byte nonce)
  - `aes256-gcm-siv` — AES‑256‑GCM‑SIV (12‑byte nonce)
- Wrap algorithm IDs:
  - `aes256-gcm-wrap-v2` — AES‑256‑GCM used to wrap a 32‑byte CEK under a 32‑byte KEK with 12‑byte nonce (ciphertext length 48 bytes)
- KDF:
  - HKDF(SHA3‑384)
  - Labels (info strings):
    - `qsfs/v2/stream/k1` — stream key K1 (AES‑256)
    - `qsfs/v2/stream/k2` — stream key K2 (ChaCha20‑Poly1305; optional)
    - `qsfs/v2/nonce-prefix` — 8‑byte per‑file nonce prefix (file_id)
    - `qsfs/kdf/v2` — Extract salt for KEK derivation
    - `qsfs/kek/v2` — Expand info for KEK derivation

## 2. Header (postcard‑encoded)
```
struct Header {
  magic:        [u8; 6]      // must equal b"QSFS2\0"
  chunk_size:   u32          // recommended ≤ 4 MiB
  file_id:      [u8; 8]      // derived; see §4.2
  blake3_resvd: [u8; 32]     // reserved (all zeroes in v2)
  recipients:   Vec<RecipientEntry>
  eph_x25519_pk:[u8; 32]     // present if hybrid; zero otherwise
  mldsa_sig:    Vec<u8>      // ML‑DSA‑87 signature bytes
  ed25519_sig:  Vec<u8>      // legacy; empty in v2
  signature_metadata: Option<SignatureMetadata>
  fin:          u8           // 1
}

struct RecipientEntry {
  label:          String     // human‑readable (not security critical)
  mlkem_ct:       Vec<u8>    // ML‑KEM‑1024 ciphertext (1568 bytes)
  wrap:           Vec<u8>    // legacy; empty in v2
  wrapped_dek:    Vec<u8>    // 48 bytes (AES‑GCM 32+16)
  wrap_nonce:     [u8; 12]   // AES‑GCM nonce for `wrapped_dek`
  x25519_pk_fpr:  [u8; 8]    // first 8 of BLAKE3(x25519_pub)
  x25519_pub:     Vec<u8>    // 32 bytes when hybrid; empty otherwise
}
```
- Decoders MUST reject: wrong `magic`, oversized `chunk_size`, wrong `mlkem_ct` length, and wrong `wrapped_dek` length.
- The reserved `blake3_resvd` MUST NOT be used for authentication or privacy decisions in v2.

## 3. Pre‑Authenticated Encoding (PAE)

To bind chunks to their header/config securely and unambiguously, QSFS v2 computes a PAE and supplies it as AEAD AAD for every encrypted chunk:

```
PAE(fields...) := "QSFS-PAE\x01" || Σ ( u64_be(len(field)) || field )
```

For v2 the AAD is:
```
AAD = PAE(
  "qsfs/v2",
  suite_id,                 // "aes256-gcm" or "aes256-gcm-siv"
  u32_be(chunk_size),
  file_id                   // 8 bytes
)
```

Rationale: length‑prefixing and a domain tag prevent ambiguity and accidental AAD drift; `file_id` commits the stream to this file instance. Implementations MAY extend the PAE with further fields in future versions, guarded by `magic` and versioned PAE prefix.

## 4. Keys and Nonces

### 4.1 KEM‑DEM and KEK derivation
- Encapsulate ML‑KEM‑1024 to obtain `mlkem_ss` and `mlkem_ct`.
- If hybrid is enabled, compute `x25519_ss = DH(eph_x_sk, recip_x25519_pk)` and set `eph_x25519_pk`.
- Derive KEK using HKDF(SHA3‑384):
```
IKM  = mlkem_ss || x25519_ss   // omit x25519_ss if not hybrid
Salt = "qsfs/kdf/v2"
Info = "qsfs/kek/v2"
KEK  = HKDF-Expand(HKDF-Extract(Salt, IKM), Info, 32)
```
- Wrap CEK (32 bytes) using `aes256-gcm-wrap-v2` under `KEK` with a fresh 12‑byte `wrap_nonce`.

### 4.2 Stream keys and file ID
- Generate a random per‑file CEK (32 bytes).
- Derive:
```
K1 = HKDF-Expand(Extract(salt=KDF_SALT, ikm=CEK), info="qsfs/v2/stream/k1", 32)
K2 = HKDF-Expand(Extract(salt=KDF_SALT, ikm=CEK), info="qsfs/v2/stream/k2", 32)  // optional
file_id = HKDF-Expand(Extract(salt=KDF_SALT, ikm=CEK), info="qsfs/v2/nonce-prefix", 8)
```
- KDF_SALT is a public per‑file salt. (In current builds, a fixed salt is used; future builds SHOULD include and bind an explicit `kdf_salt` in the header.)

### 4.3 Chunk nonces
- For chunk number `i` (u32), the 96‑bit nonce is:
```
nonce = file_id(8 bytes) || u32_be(i)
```
- Implementations MUST check chunk count limits and ordering.

## 5. AEAD and chunk framing
- QSFS v2 supports suites:
  - `aes256-gcm-siv` (RECOMMENDED)
  - `aes256-gcm`
- Every chunk is independently encrypted:
```
ct_i = AEAD_Encrypt(K1, nonce_i, AAD, pt_i)
frame_i = u32_be(i) || u32_be(len(ct_i)) || ct_i
```
- On decrypt, verify frame ordering, length bounds, and AEAD tag; write plaintext sequentially.

## 6. Signatures
- Canonical header (deterministic) is serialized excluding signature fields; sign with ML‑DSA‑87.
- `signature_metadata` carries signer_id (sha256(pk)), algorithm id, and base64 pk.
- Verification policy is host‑local (trustdb). Decoders MUST fail if signature is present but invalid; unsigned decrypt only with explicit override.

## 7. Deterministic KAT Vectors

These vectors demonstrate the exact KDFs, PAE, and a single‑chunk encrypt under AES‑GCM‑SIV. All hex values are lowercase, no separators.

Inputs:
- CEK = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
- KDF_SALT = "QSFSv2-KDF-SALT!" (5153465376322d4b44462d53414c5421)
- mlkem_ss = 303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f
- x25519_ss = 505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f
- suite_id = "aes256-gcm-siv"
- chunk_size = 131072 (00020000)
- pt (chunk 0) = "hello qsfs v2\n" (68656c6c6f20717366732076320a)

Derived:
- k1_aes256 = 43a364585e3dd38530f880a1286aa437cb9d22e3cfa636fafdf416fbbc434342
- k2_chacha = eabf24e4f7bddc24fdf5fffe08cb930423570ac03bfe739c4844c1d17ffcbfd6
- file_id = 8eaf015d9b2c1528
- KEK = b48776ae06e112d1115e002a687cb49b692e585eb37edb36e9ae3b2e1ddcee12
- wrap_nonce = 000102030405060708090a0b
- wrapped_cek_gcm = d0e68aa6ff9640c38b95c05c35314c53a3273536904bf2463ea70edb7ddcf2294890bdc7ccb2d1026d85c49e8d52d505

PAE (AAD):
- PAE("qsfs/v2","aes256-gcm-siv",chunk_size_be,file_id) with prefix "QSFS-PAE\x01" →
  pae = 515346532d504145010000000000000007717366732f7632000000000000000e6165733235362d67636d2d73697600000000000000040002000000000000000000088eaf015d9b2c1528

Chunk 0 (AES‑256‑GCM‑SIV):
- nonce0 = file_id || 00000000 → 8eaf015d9b2c152800000000
- ct0 = 9e07a7e2ba36c2d0f050d9575fd40b19c4ab226290ced7cd3851140476ad

An implementation that reproduces these values is conformant for the specified sub‑steps.

## 8. Security and operational guidance
- Default suite SHOULD be `aes256-gcm-siv` in release builds.
- Treat KDF parameters and suite id as part of the configuration committed by AAD.
- Enforce chunk ordering and conservative size limits.
- Signer at rest: Argon2id defaults SHOULD target ≥256 MiB memory, t≥3; encode (m,t,p) in the encrypted key header for migration.
- Zeroize CEK, PRKs, passphrases promptly.

---
This document is normative for QSFS v2.
