use serde::{Serialize, Deserialize};
use crate::suite::SuiteId;
use crate::pae::pae_v2_compat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientEntry {
    /// Human-readable label
    pub label: String,
    /// ML-KEM ciphertext
    #[serde(with="serde_bytes")]
    pub mlkem_ct: Vec<u8>,
    /// Legacy wrapped CEK (pre-GCM, 32 bytes) — kept for backward-compat
    #[serde(with="serde_bytes")]
    pub wrap: Vec<u8>,
    /// AES-GCM-wrapped DEK (must be 48 bytes)
    #[serde(default, with="serde_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// Nonce for wrapped_dek (12 bytes)
    #[serde(default)]
    pub wrap_nonce: [u8; 12],
    /// X25519 recipient PK fingerprint (first 8 of BLAKE3)
    #[serde(default)]
    pub x25519_pk_fpr: [u8; 8],
    /// X25519 recipient PK (legacy/debug; presence indicates hybrid used)
    #[serde(default, with="serde_bytes")]
    pub x25519_pub: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    /// Magic bytes for format identification
    pub magic: [u8; 6],
    /// Chunk size for streaming
    pub chunk_size: u32,
    /// File identifier for nonce derivation
    pub file_id: [u8; 8],
    /// Reserved (previously plaintext hash). Kept for compatibility; zeroed.
    #[serde(default)]
    pub blake3_of_plain: [u8; 32],
    /// AEAD suite identifier
    pub suite: SuiteId,
    /// Optional per-file public KDF salt (v2.1). None for v2.0 files.
    #[serde(default)]
    pub kdf_salt: Option<[u8; 32]>,
    /// Recipients with KEM ciphertexts and wrapped CEKs
    pub recipients: Vec<RecipientEntry>,
    /// Ephemeral X25519 public key (hybrid)
    #[serde(default)]
    pub eph_x25519_pk: [u8; 32],
    /// ML-DSA-87 signature (FIPS 204)
    #[serde(default, with="serde_bytes")]
    pub mldsa_sig: Vec<u8>,
    /// Ed25519 signature (legacy/hybrid)
    #[serde(default, with="serde_bytes")]
    pub ed25519_sig: Vec<u8>,
    /// Signature metadata
    #[serde(default)]
    pub signature_metadata: Option<SignatureMetadata>,
    /// FIN marker
    pub fin: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String, // base64 encoded
}

impl Header {
    pub fn aead_aad(&self) -> Vec<u8> {
        // Spec-accurate PAE/AAD with backward-compat
        pae_v2_compat(self)
    }
}
