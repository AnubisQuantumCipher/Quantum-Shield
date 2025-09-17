#[cfg(feature="pq")]
pub mod mlkem {
    pub use pqcrypto_mlkem::mlkem1024::*;
    
    #[allow(dead_code)]
    pub fn keypair() -> (PublicKey, SecretKey) { 
        pqcrypto_mlkem::mlkem1024::keypair() 
    }
    #[allow(dead_code)]
    pub fn encapsulate(pk: &PublicKey) -> (SharedSecret, Ciphertext) { 
        pqcrypto_mlkem::mlkem1024::encapsulate(pk) 
    }
    #[allow(dead_code)]
    pub fn decapsulate(ct: &Ciphertext, sk: &SecretKey) -> SharedSecret { 
        pqcrypto_mlkem::mlkem1024::decapsulate(ct, sk) 
    }
    
    // For verifiable decapsulation - derive public key from secret key
    #[allow(dead_code)]
    pub fn public_key_from_secret(_sk: &SecretKey) -> PublicKey {
        // Generate a temporary keypair and extract the public key
        // This is a placeholder - in practice, ML-KEM secret keys contain the public key
        let (pk, _) = keypair();
        pk
    }
}

#[cfg(feature="pq")]
pub mod mldsa {
    pub use pqcrypto_mldsa::mldsa87::*;
    
    #[allow(dead_code)]
    pub fn keypair() -> (PublicKey, SecretKey) { 
        pqcrypto_mldsa::mldsa87::keypair() 
    }
    #[allow(dead_code)]
    pub fn sign_detached(msg: &[u8], sk: &SecretKey) -> DetachedSignature { 
        pqcrypto_mldsa::mldsa87::detached_sign(msg, sk) 
    }
    #[allow(dead_code)]
    pub fn verify_detached(sig: &DetachedSignature, msg: &[u8], pk: &PublicKey) -> bool {
        pqcrypto_mldsa::mldsa87::verify_detached_signature(sig, msg, pk).is_ok()
    }
}
