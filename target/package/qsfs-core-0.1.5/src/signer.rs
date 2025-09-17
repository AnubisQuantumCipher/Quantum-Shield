use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::fs;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use argon2::{Argon2, Params, Algorithm, Version};
use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

#[cfg(feature="pq")]
use pqcrypto_mldsa::mldsa87::{keypair, detached_sign, PublicKey, SecretKey, DetachedSignature};
#[cfg(feature="pq")]
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, DetachedSignature as DetachedSignatureTrait};

/// ML-DSA-87 signer with secure key management
pub struct Signer {
    pub sk: SecretKey,  // pqcrypto SecretKey is opaque; we encrypt at rest
    pub pk: PublicKey,
    pub id: [u8; 32], // SHA-256 of public key
}

impl Signer {
    /// Generate a new ML-DSA-87 signer
    pub fn generate() -> Result<Self> {
        #[cfg(feature="pq")]
        {
            let (pk, sk) = keypair();
            let mut hasher = Sha256::new();
            hasher.update(pk.as_bytes());
            let mut id = [0u8; 32];
            id.copy_from_slice(&hasher.finalize());
            
            Ok(Signer {
                sk,
                pk,
                id,
            })
        }
        #[cfg(not(feature="pq"))]
        {
            Err(anyhow::anyhow!("ML-DSA-87 not available without 'pq' feature"))
        }
    }
    
    /// Load signer from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = fs::read(&path)?;
        // Encrypted blob: magic | salt(16) | nonce(12) | ct
        if data.starts_with(b"QSFS_SIGNER\x01") {
            if data.len() < 12 + 16 + 12 + 16 { // magic + salt + nonce + tag
                return Err(anyhow::anyhow!("Invalid encrypted signer file"));
            }
            let salt = &data[12..28];
            let nonce = &data[28..40];
            let ct = &data[40..];
            let pass = std::env::var("QSFS_SIGNER_PASSPHRASE")
                .map_err(|_| anyhow::anyhow!("QSFS_SIGNER_PASSPHRASE not set for encrypted signer"))?;
            let key = derive_key_argon2id(pass.as_bytes(), salt)?;
            let mut nonce_arr = [0u8; 12];
            nonce_arr.copy_from_slice(nonce);
            let pt = aead_decrypt(&key, &nonce_arr, ct)?;
            return Self::from_plain_bytes(&pt);
        }
        if data.len() < 32 {
            return Err(anyhow::anyhow!("Invalid signer file format"));
        }
        
        // Extract ID (first 32 bytes)
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[0..32]);
        
        // Extract public key
        let pk_len = pqcrypto_mldsa::mldsa87::public_key_bytes();
        if data.len() < 32 + pk_len {
            return Err(anyhow::anyhow!("Invalid signer file format"));
        }
        let pk_bytes = &data[32..32 + pk_len];
        let pk = PublicKey::from_bytes(pk_bytes).map_err(|_| anyhow::anyhow!("Invalid public key"))?;
        
        // Extract secret key
        let sk_bytes = &data[32 + pk_len..];
        let sk = SecretKey::from_bytes(sk_bytes).map_err(|_| anyhow::anyhow!("Invalid secret key"))?;
        
        Ok(Signer {
            sk,
            pk,
            id,
        })
    }
    
    /// Save signer to file with secure permissions
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.id);
        data.extend_from_slice(self.pk.as_bytes());
        data.extend_from_slice(self.sk.as_bytes());
        
        fs::write(&path, &data)?;
        
        // Set secure permissions (0600)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        
        Ok(())
    }

    /// Save signer in encrypted format using passphrase in env (QSFS_SIGNER_PASSPHRASE)
    pub fn save_to_file_encrypted<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pass = std::env::var("QSFS_SIGNER_PASSPHRASE")
            .map_err(|_| anyhow::anyhow!("QSFS_SIGNER_PASSPHRASE not set"))?;
        let mut pt = Vec::new();
        pt.extend_from_slice(&self.id);
        pt.extend_from_slice(self.pk.as_bytes());
        pt.extend_from_slice(self.sk.as_bytes());
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)?;
        let key = derive_key_argon2id(pass.as_bytes(), &salt)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)?;
        let ct = aead_encrypt(&key, &nonce, &pt)?;
        let mut blob = Vec::with_capacity(12 + 16 + 12 + ct.len());
        blob.extend_from_slice(b"QSFS_SIGNER\x01");
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        fs::write(&path, &blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }
    
    /// Sign data with ML-DSA-87
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature="pq")]
        {
            let sig = detached_sign(data, &self.sk);
            Ok(sig.as_bytes().to_vec())
        }
        #[cfg(not(feature="pq"))]
        {
            Err(anyhow::anyhow!("ML-DSA-87 not available without 'pq' feature"))
        }
    }
    
    /// Get signer ID as hex string
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }
    
    /// Get public key as base64
    pub fn public_key_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.pk.as_bytes())
    }
    /// Construct signer from legacy plaintext bytes (id|pk|sk)
    fn from_plain_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 32 { return Err(anyhow::anyhow!("Invalid signer bytes")); }
        let mut id = [0u8; 32];
        id.copy_from_slice(&data[0..32]);
        let pk_len = pqcrypto_mldsa::mldsa87::public_key_bytes();
        if data.len() < 32 + pk_len { return Err(anyhow::anyhow!("Invalid signer bytes")); }
        let pk_bytes = &data[32..32 + pk_len];
        let sk_bytes = &data[32 + pk_len..];
        let pk = PublicKey::from_bytes(pk_bytes).map_err(|_| anyhow::anyhow!("Invalid signer bytes (pk)"))?;
        let sk = SecretKey::from_bytes(sk_bytes).map_err(|_| anyhow::anyhow!("Invalid signer bytes (sk)"))?;
        Ok(Signer { sk, pk, id })
    }
}

/// Verify ML-DSA-87 signature
pub fn verify_signature(data: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
    #[cfg(feature="pq")]
    {
        let pk = PublicKey::from_bytes(public_key).map_err(|_| anyhow::anyhow!("Invalid public key"))?;
        let sig = DetachedSignature::from_bytes(signature).map_err(|_| anyhow::anyhow!("Invalid signature"))?;
        Ok(pqcrypto_mldsa::mldsa87::verify_detached_signature(&sig, data, &pk).is_ok())
    }
    #[cfg(not(feature="pq"))]
    {
        Err(anyhow::anyhow!("ML-DSA-87 not available without 'pq' feature"))
    }
}

/// Trust store entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    pub signer_id: String,
    pub public_key: String, // base64 encoded
    pub note: String,
    pub added_at: u64, // Unix timestamp
}

/// Trust store manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub entries: HashMap<String, TrustEntry>,
}

impl TrustStore {
    /// Create new empty trust store
    pub fn new() -> Self {
        TrustStore {
            entries: HashMap::new(),
        }
    }
    
    /// Load trust store from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(TrustStore::new());
        }
        
        let data = fs::read_to_string(path)?;
        let store: TrustStore = serde_json::from_str(&data)?;
        Ok(store)
    }
    
    /// Save trust store to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let data = serde_json::to_string_pretty(self)?;
        fs::write(&path, data)?;
        Ok(())
    }
    
    /// Add signer to trust store
    pub fn add_signer(&mut self, signer_id: String, public_key: String, note: String) -> Result<()> {
        let entry = TrustEntry {
            signer_id: signer_id.clone(),
            public_key,
            note,
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };
        
        self.entries.insert(signer_id, entry);
        Ok(())
    }
    
    /// Remove signer from trust store
    pub fn remove_signer(&mut self, signer_id: &str) -> bool {
        self.entries.remove(signer_id).is_some()
    }
    
    /// Check if signer is trusted
    pub fn is_trusted(&self, signer_id: &str) -> bool {
        self.entries.contains_key(signer_id)
    }
    
    /// Get public key for signer
    pub fn get_public_key(&self, signer_id: &str) -> Option<&str> {
        self.entries.get(signer_id).map(|e| e.public_key.as_str())
    }
    
    /// List all trusted signers
    pub fn list_signers(&self) -> Vec<&TrustEntry> {
        self.entries.values().collect()
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default signer path
pub fn default_signer_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
    let qsfs_dir = home.join(".qsfs");
    fs::create_dir_all(&qsfs_dir)?;
    Ok(qsfs_dir.join("signer.mldsa87"))
}

/// Get default trust store path
pub fn default_trustdb_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?;
    let qsfs_dir = home.join(".qsfs");
    fs::create_dir_all(&qsfs_dir)?;
    Ok(qsfs_dir.join("trustdb"))
}

/// Auto-provision signer if it doesn't exist
pub fn auto_provision_signer() -> Result<Signer> {
    let signer_path = default_signer_path()?;
    let trustdb_path = default_trustdb_path()?;
    
    if signer_path.exists() {
        return Signer::load_from_file(&signer_path);
    }
    
    // Generate new signer
    let signer = Signer::generate()?;
    if std::env::var("QSFS_SIGNER_PASSPHRASE").is_ok() {
        signer.save_to_file_encrypted(&signer_path)?;
    } else {
        signer.save_to_file(&signer_path)?;
    }
    
    // Add to trust store (self-trust)
    let mut trust_store = TrustStore::load_from_file(&trustdb_path)?;
    trust_store.add_signer(
        signer.id_hex(),
        signer.public_key_base64(),
        "Self-generated signer".to_string(),
    )?;
    trust_store.save_to_file(&trustdb_path)?;
    
    println!("✅ Auto-generated ML-DSA-87 signer: {}", signer.id_hex());
    
    Ok(signer)
}

// === Internal helpers for passphrase-protected signer ===
fn derive_key_argon2id(pass: &[u8], salt: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    let params = Params::new(32, 19456, 2, None)
        .map_err(|e| anyhow::anyhow!("argon2 params: {}", e))?; // 19MB, 2 iters
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon.hash_password_into(pass, salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 derive: {}", e))?;
    Ok(out)
}

fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    Ok(cipher.encrypt(Nonce::from_slice(nonce), pt).map_err(|_| anyhow::anyhow!("signer encrypt"))?)
}

fn aead_decrypt(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    Ok(cipher.decrypt(Nonce::from_slice(nonce), ct).map_err(|_| anyhow::anyhow!("signer decrypt"))?)
}
