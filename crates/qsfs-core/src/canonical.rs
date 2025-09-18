use anyhow::Result;
use crate::header::Header;
use base64::{engine::general_purpose, Engine as _};

/// Canonical header serialization for signing
/// 
/// Creates a deterministic, byte-exact representation of the header
/// that can be signed with ML-DSA-87. The canonical format excludes
/// signature fields and uses stable ordering.
pub struct CanonicalHeader;

impl CanonicalHeader {
    /// Serialize header to canonical bytes for signing
    pub fn serialize(header: &Header) -> Result<Vec<u8>> {
        let mut canonical = Vec::new();
        
        // Header format version (QSFS v2)
        canonical.extend_from_slice(b"qsfs/v2\n");
        
        // Parameters line
        canonical.extend_from_slice(b"params: aesgcm256 mlkem1024\n");
        
        // Chunk size
        canonical.extend_from_slice(format!("chunk: {}\n", header.chunk_size).as_bytes());
        
        // Context (file ID as base64)
        let context_b64 = general_purpose::STANDARD.encode(header.file_id);
        canonical.extend_from_slice(format!("context: {}\n", context_b64).as_bytes());
        
        // AEAD algorithm
        canonical.extend_from_slice(b"aead: aes256gcm-v2\n");
        
        // Recipients (deterministic ordering by ML-KEM ct bytes)
        let mut recipients = header.recipients.clone();
        recipients.sort_by(|a, b| a.mlkem_ct.cmp(&b.mlkem_ct));

        for r in &recipients {
            let ct_b64 = general_purpose::STANDARD.encode(&r.mlkem_ct);
            let wrap_legacy_b64 = general_purpose::STANDARD.encode(&r.wrap);
            let wrapped_b64 = general_purpose::STANDARD.encode(&r.wrapped_dek);
            let nonce_b64 = general_purpose::STANDARD.encode(r.wrap_nonce);
            let xpub_b64 = general_purpose::STANDARD.encode(&r.x25519_pub);
            let xfpr_hex = {
                let mut s = String::with_capacity(16);
                for b in &r.x25519_pk_fpr { s.push_str(&format!("{:02x}", b)); }
                s
            };

            // Include both legacy wrap and new AEAD wrap fields under clear keys
            canonical.extend_from_slice(
                format!(
                    "recip: label={} ct={} wrap_legacy={} gcm_nonce={} gcm_wrap={} x25519_pk={} x25519_fpr={}\n",
                    r.label, ct_b64, wrap_legacy_b64, nonce_b64, wrapped_b64, xpub_b64, xfpr_hex
                ).as_bytes()
            );
        }
        
        // Reserved hash field (deprecated)
        let hash_b64 = general_purpose::STANDARD.encode(header.blake3_of_plain);
        canonical.extend_from_slice(format!("hash_resvd: {}\n", hash_b64).as_bytes());
        
        // Ephemeral X25519 (hybrid)
        let eph_b64 = general_purpose::STANDARD.encode(header.eph_x25519_pk);
        canonical.extend_from_slice(format!("ephx25519: {}\n", eph_b64).as_bytes());

        // FIN marker
        canonical.extend_from_slice(format!("fin: {}\n", header.fin).as_bytes());
        
        Ok(canonical)
    }
    
    /// Verify that canonical serialization is deterministic
    pub fn verify_deterministic(header: &Header) -> Result<bool> {
        let canonical1 = Self::serialize(header)?;
        let canonical2 = Self::serialize(header)?;
        Ok(canonical1 == canonical2)
    }
    
    /// Create a canonical representation for display/debugging
    pub fn to_string(header: &Header) -> Result<String> {
        let canonical = Self::serialize(header)?;
        Ok(String::from_utf8(canonical)?)
    }
}

/// Signature metadata for header
#[derive(Debug, Clone)]
pub struct SignatureMetadata {
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String, // base64 encoded
    pub signature: String,  // base64 encoded
}

impl SignatureMetadata {
    /// Create new signature metadata
    pub fn new(signer_id: String, public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        SignatureMetadata {
            signer_id,
            algorithm: "ml-dsa-87".to_string(),
            public_key: general_purpose::STANDARD.encode(public_key),
            signature: general_purpose::STANDARD.encode(signature),
        }
    }
    
    /// Serialize signature metadata to header lines
    pub fn to_header_lines(&self) -> Vec<String> {
        vec![
            format!("signer: {}", self.signer_id),
            format!("sigalg: {}", self.algorithm),
            format!("sigpub: {}", self.public_key),
            format!("sig: {}", self.signature),
        ]
    }
    
    /// Parse signature metadata from header lines
    pub fn from_header_lines(lines: &[String]) -> Result<Self> {
        let mut signer_id = None;
        let mut algorithm = None;
        let mut public_key = None;
        let mut signature = None;
        
        for line in lines {
            if let Some(value) = line.strip_prefix("signer: ") {
                signer_id = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("sigalg: ") {
                algorithm = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("sigpub: ") {
                public_key = Some(value.to_string());
            } else if let Some(value) = line.strip_prefix("sig: ") {
                signature = Some(value.to_string());
            }
        }
        
        Ok(SignatureMetadata {
            signer_id: signer_id.ok_or_else(|| anyhow::anyhow!("Missing signer field"))?,
            algorithm: algorithm.ok_or_else(|| anyhow::anyhow!("Missing sigalg field"))?,
            public_key: public_key.ok_or_else(|| anyhow::anyhow!("Missing sigpub field"))?,
            signature: signature.ok_or_else(|| anyhow::anyhow!("Missing sig field"))?,
        })
    }
    
    /// Get public key as bytes
    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|e| anyhow::anyhow!("Invalid public key base64: {}", e))
    }
    
    /// Get signature as bytes
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        general_purpose::STANDARD
            .decode(&self.signature)
            .map_err(|e| anyhow::anyhow!("Invalid signature base64: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Header, RecipientEntry};
    
    fn create_test_header() -> Header {
        Header {
            magic: *b"QSFS2\0",
            chunk_size: 1048576,
            file_id: [1, 2, 3, 4, 5, 6, 7, 8],
            blake3_of_plain: [0u8; 32],
            suite: SuiteId::current(),
            kdf_salt: None,
            recipients: vec![
                RecipientEntry {
                    label: "alice".to_string(),
                    mlkem_ct: vec![1, 2, 3, 4],
                    wrap: vec![5, 6, 7, 8],
                    wrapped_dek: Vec::new(),
                    wrap_nonce: [0u8;12],
                    x25519_pk_fpr: [0u8;8],
                    x25519_pub: vec![],
                },
                RecipientEntry {
                    label: "bob".to_string(),
                    mlkem_ct: vec![9, 10, 11, 12],
                    wrap: vec![13, 14, 15, 16],
                    wrapped_dek: Vec::new(),
                    wrap_nonce: [0u8;12],
                    x25519_pk_fpr: [0u8;8],
                    x25519_pub: vec![],
                },
            ],
            eph_x25519_pk: [0u8;32],
            mldsa_sig: vec![],
            ed25519_sig: vec![],
            signature_metadata: None,
            fin: 1,
        }
    }
    
    #[test]
    fn test_canonical_serialization() {
        let header = create_test_header();
        let canonical = CanonicalHeader::serialize(&header).unwrap();
        
        // Should be valid UTF-8
        let canonical_str = String::from_utf8(canonical.clone()).unwrap();
        
        // Should contain expected fields
        assert!(canonical_str.contains("qsfs/v2"));
        assert!(canonical_str.contains("params: aesgcm256 mlkem1024"));
        assert!(canonical_str.contains("chunk: 1048576"));
        assert!(canonical_str.contains("aead: aes256gcm-v2"));
        assert!(canonical_str.contains("recip: label=alice"));
        assert!(canonical_str.contains("recip: label=bob"));
        assert!(canonical_str.contains("ephx25519:"));
        assert!(canonical_str.contains("fin: 1"));
    }
    
    #[test]
    fn test_deterministic_serialization() {
        let header = create_test_header();
        assert!(CanonicalHeader::verify_deterministic(&header).unwrap());
    }
    
    #[test]
    fn test_recipient_ordering() {
        let mut header = create_test_header();
        
        // Reverse recipient order
        header.recipients.reverse();
        
        let canonical1 = CanonicalHeader::serialize(&header).unwrap();
        
        // Should still produce same canonical form (sorted deterministically)
        header.recipients.reverse();
        let canonical2 = CanonicalHeader::serialize(&header).unwrap();
        
        assert_eq!(canonical1, canonical2);
    }
}
