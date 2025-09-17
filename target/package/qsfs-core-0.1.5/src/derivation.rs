use hkdf::Hkdf;
use sha3::Sha3_384;
use zeroize::Zeroize;
use secrecy::{Secret, ExposeSecret};
use rand::RngCore;

pub struct ContentKeys {
    pub aes_k1: Secret<[u8; 32]>,
    #[allow(dead_code)]
    pub chacha_k2: Secret<[u8; 32]>,
}

impl Drop for ContentKeys {
    fn drop(&mut self) {
        // Secrecy handles zeroization automatically
    }
}

pub struct ContentEncryptionKey(Secret<[u8; 32]>);

impl ContentEncryptionKey {
    pub fn generate() -> anyhow::Result<Self> {
        let mut cek = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut cek);
        Ok(ContentEncryptionKey(Secret::new(cek)))
    }
    
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl Drop for ContentEncryptionKey {
    fn drop(&mut self) {
        // Secrecy handles zeroization automatically
    }
}

pub fn hkdf_sha384_expand(ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    // HKDF-Extract with a fixed context salt to ensure domain separation
    let salt = b"qsfs/hkdf/v2";
    let hk = Hkdf::<Sha3_384>::new(Some(salt), ikm);
    let mut output = vec![0u8; len];
    hk.expand(info, &mut output).unwrap();
    output
}

pub fn hkdf_expand_keys(cek: &[u8; 32], confirm: Option<&[u8]>) -> ContentKeys {
    let mut info_k1 = b"qsfs/stream/k1".to_vec();
    let mut info_k2 = b"qsfs/stream/k2".to_vec();
    
    if let Some(conf) = confirm {
        info_k1.extend_from_slice(conf);
        info_k2.extend_from_slice(conf);
    }
    
    let k1_bytes = hkdf_sha384_expand(cek, &info_k1, 32);
    let k2_bytes = hkdf_sha384_expand(cek, &info_k2, 32);
    
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    k1.copy_from_slice(&k1_bytes);
    k2.copy_from_slice(&k2_bytes);
    
    ContentKeys { 
        aes_k1: Secret::new(k1), 
        chacha_k2: Secret::new(k2) 
    }
}

pub fn derive_file_nonce_seed(cek: &[u8; 32]) -> [u8; 8] {
    let output = hkdf_sha384_expand(cek, b"qsfs/nonce-prefix", 8);
    let mut seed = [0u8; 8];
    seed.copy_from_slice(&output);
    seed
}

/// Derive a KEK (32 bytes) from ML-KEM shared secret and X25519 shared secret
pub fn derive_kek(mlkem_ss: &[u8], x25519_ss: &[u8], kdf_salt_opt: Option<&[u8]>) -> [u8; 32] {
    // IKM = concatenation of shared secrets
    let mut ikm = Vec::with_capacity(mlkem_ss.len() + x25519_ss.len());
    ikm.extend_from_slice(mlkem_ss);
    ikm.extend_from_slice(x25519_ss);

    // HKDF-Extract with KEK-specific salt (v2.1: per-file kdf_salt) or v2.0 fallback
    let salt = kdf_salt_opt.unwrap_or(b"qsfs/kdf/v2");
    let hk = Hkdf::<Sha3_384>::new(Some(salt), &ikm);
    let mut out = [0u8; 32];
    hk.expand(b"qsfs/kek/v2", &mut out).expect("HKDF expand");
    out
}

/// Wrap a 32-byte DEK with AES-256-GCM under the KEK and 12-byte nonce
pub fn wrap_dek(kek: &[u8; 32], nonce: &[u8; 12], dek: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}, Nonce};
    let cipher = Aes256Gcm::new_from_slice(kek).unwrap();
    let n = Nonce::from_slice(nonce);
    let ct = cipher.encrypt(n, dek.as_slice())
        .map_err(|_| anyhow::anyhow!("DEK wrap failed"))?;
    Ok(ct)
}

/// Unwrap DEK; returns 32 bytes if tag valid
pub fn unwrap_dek(kek: &[u8; 32], nonce: &[u8; 12], wrapped: &[u8]) -> anyhow::Result<[u8; 32]> {
    use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}, Nonce};
    if wrapped.len() != 48 { return Err(anyhow::anyhow!("Invalid wrapped_dek length")); }
    let cipher = Aes256Gcm::new_from_slice(kek).unwrap();
    let n = Nonce::from_slice(nonce);
    let pt = cipher.decrypt(n, wrapped)
        .map_err(|_| anyhow::anyhow!("DEK unwrap failed"))?;
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&pt);
    Ok(dek)
}

// Legacy XOR wrap (pre-GCM)
#[allow(dead_code)]
pub fn unwrap_cek_legacy(wrapped: &[u8], shared_secret: &[u8]) -> anyhow::Result<[u8; 32]> {
    if wrapped.len() != 32 { return Err(anyhow::anyhow!("Invalid wrapped CEK length")); }
    let keystream = hkdf_sha384_expand(shared_secret, b"qsfs/cek-wrap", 32);
    let mut cek = [0u8; 32];
    for (i, (w, k)) in wrapped.iter().zip(keystream.iter()).enumerate() {
        cek[i] = w ^ k;
    }
    Ok(cek)
}

#[allow(dead_code)]
pub fn zeroize_bytes(mut v: Vec<u8>) {
    v.zeroize();
}
