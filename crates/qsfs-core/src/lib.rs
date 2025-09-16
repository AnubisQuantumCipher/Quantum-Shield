pub mod derivation;
mod header;
mod pq;
mod streaming;
mod security;
pub mod suite;
pub mod pae;
pub mod signer;
pub mod canonical;

use anyhow::Result;
use derivation::{derive_file_nonce_seed, hkdf_expand_keys, ContentEncryptionKey, derive_kek, wrap_dek, unwrap_dek};
pub use header::{Header, RecipientEntry, SignatureMetadata};
use crate::suite::SuiteId;
use pq::mlkem;
use tokio::{fs::File, io::AsyncReadExt};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use std::io::Write;
use secrecy::ExposeSecret;
use tempfile::NamedTempFile;
use std::path::Path;
use security::{disable_core_dumps, set_secure_permissions};
pub use signer::{Signer, TrustStore, verify_signature, default_trustdb_path, auto_provision_signer};
pub use canonical::{CanonicalHeader, SignatureMetadata as CanonicalSignatureMetadata};

#[cfg(feature="pq")]
use pqcrypto_traits::kem::{SharedSecret as SharedSecretTrait, Ciphertext as CiphertextTrait};
#[cfg(feature="pq")]
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;

pub struct SealRequest<'a> {
    pub input_path: &'a str,
    pub recipients: Vec<(String, pqcrypto_mlkem::mlkem1024::PublicKey, [u8;32])>,
    pub header_sign_mldsa_sk: Option<pqcrypto_mldsa::mldsa87::SecretKey>,
    pub chunk_size: usize,
    pub signer: Option<&'a Signer>,
}

pub struct UnsealContext<'a> {
    pub mlkem_sk: &'a pqcrypto_mlkem::mlkem1024::SecretKey,
    pub x25519_sk: Option<[u8;32]>,
    pub allow_unsigned: bool,
    pub trust_any_signer: bool,
}

pub async fn seal(req: SealRequest<'_>, output_path: &str) -> Result<()> {
    // Disable core dumps for security
    disable_core_dumps().ok();
    
    // 1) Prepare header (no plaintext fingerprint in clear)
    
    // 2) Generate CEK and wrap for each recipient
    let cek = ContentEncryptionKey::generate()?;
    let mut recipients = Vec::new();
    
    // Ephemeral X25519 key for this file
    #[cfg(feature="hybrid-x25519")]
    let eph_x_sk = {
        let rng = rand::rngs::OsRng;
        x25519_dalek::StaticSecret::random_from_rng(rng)
    };
    #[cfg(feature="hybrid-x25519")]
    let eph_x_pk = x25519_dalek::PublicKey::from(&eph_x_sk);

    // Generate per-file kdf_salt (v2.1)
    let mut kdf_salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut kdf_salt);

    for (label, mlkem_pk, recip_x25519_pk_bytes) in req.recipients {
        let (ss, ct) = mlkem::encapsulate(&mlkem_pk);

        #[cfg(feature="hybrid-x25519")]
        let kek = {
            let recip_x_pk = x25519_dalek::PublicKey::from(recip_x25519_pk_bytes);
            let x_ss = eph_x_sk.diffie_hellman(&recip_x_pk);
            derive_kek(ss.as_bytes(), x_ss.as_bytes(), Some(&kdf_salt))
        };

    #[cfg(not(feature="hybrid-x25519"))]
    let kek = {
            // Always KDF the shared secret (even when not hybrid)
            derive_kek(ss.as_bytes(), &[], Some(&kdf_salt))
        };

        // Wrap DEK under KEK
        let mut wrap_nonce = [0u8;12];
        rand::rngs::OsRng.fill_bytes(&mut wrap_nonce);
        let wrapped_dek = wrap_dek(&kek, &wrap_nonce, cek.expose_secret())?;

        // Recipient fingerprint
        let x25519_pk_fpr = {
            let h = blake3::hash(&recip_x25519_pk_bytes);
            let mut f = [0u8;8]; f.copy_from_slice(&h.as_bytes()[..8]); f
        };

        recipients.push(RecipientEntry {
            label,
            mlkem_ct: ct.as_bytes().to_vec(),
            wrap: wrapped_dek.clone(), // legacy mirror
            wrapped_dek,
            wrap_nonce,
            x25519_pk_fpr,
            x25519_pub: recip_x25519_pk_bytes.to_vec(),
        });
    }

    // 4) Derive keys and file-id from CEK with enhanced domain separation
    let confirm = b"qsfs_confirm_v2";
    let keys = hkdf_expand_keys(cek.expose_secret(), Some(confirm));
    let file_id = derive_file_nonce_seed(cek.expose_secret());
    
    let mut hdr = header::Header {
        magic: *b"QSFS2\0",
        chunk_size: req.chunk_size as u32,
        file_id,
        blake3_of_plain: [0u8;32],
        suite: SuiteId::current(),
        kdf_salt: Some(kdf_salt),
        recipients,
        #[cfg(feature="hybrid-x25519")]
        eph_x25519_pk: *eph_x_pk.as_bytes(),
        #[cfg(not(feature="hybrid-x25519"))]
        eph_x25519_pk: [0u8;32],
        mldsa_sig: vec![],
        ed25519_sig: vec![],
        signature_metadata: None,
        fin: 1,
    };
    
    // Sign header with ML-DSA-87 if signer is provided
    if let Some(signer) = req.signer {
        let canonical_bytes = CanonicalHeader::serialize(&hdr)?;
        let signature = signer.sign(&canonical_bytes)?;
        
        let sig_metadata = CanonicalSignatureMetadata::new(
            signer.id_hex(),
            signer.pk.as_bytes().to_vec(),
            signature.clone(),
        );
        
        hdr.mldsa_sig = signature;
        hdr.signature_metadata = Some(SignatureMetadata {
            signer_id: sig_metadata.signer_id,
            algorithm: sig_metadata.algorithm,
            public_key: sig_metadata.public_key,
        });
    }
    
    // 5) Atomic write: use temporary file with secure permissions
    let output_dir = Path::new(output_path).parent().unwrap_or(Path::new("."));
    let mut temp_file = NamedTempFile::new_in(output_dir)?;
    
    // Set secure permissions on temporary file
    set_secure_permissions(temp_file.path()).ok();
    
    let hdr_bytes = postcard::to_allocvec(&hdr)?;

    // Write header length + header + encrypted stream
    temp_file.write_all(&(hdr_bytes.len() as u32).to_be_bytes())?;
    temp_file.write_all(&hdr_bytes)?;

    let aad = hdr.aead_aad();
    streaming::encrypt_stream(
        req.input_path,
        temp_file.as_file_mut(),
        req.chunk_size,
        file_id,
        &aad,
        keys.aes_k1.expose_secret(),
        None,
    ).await?;

    // Ensure data is written to disk before atomic rename
    temp_file.as_file_mut().sync_all()?;
    
    // Atomic rename
    temp_file.persist(output_path)?;
    
    Ok(())
}

pub async fn unseal(mut input: File, output_path: &str, ctx: UnsealContext<'_>) -> Result<()> {
    // Disable core dumps for security
    disable_core_dumps().ok();
    
    // 1) Read header length and header
    let mut len_buf = [0u8; 4];
    input.read_exact(&mut len_buf).await?;
    let hdr_len = u32::from_be_bytes(len_buf) as usize;
    
    if hdr_len > 1024 * 1024 {
        return Err(anyhow::anyhow!("Header too large: {}", hdr_len));
    }
    
    let mut hdr_buf = vec![0u8; hdr_len];
    input.read_exact(&mut hdr_buf).await?;
    let hdr: Header = postcard::from_bytes(&hdr_buf)?;
    // Enforce magic/version
    if hdr.magic != *b"QSFS2\0" {
        return Err(anyhow::anyhow!("Unrecognized file format (bad magic)"));
    }
    
    // 2) Verify signature if present (default behavior)
    if !hdr.mldsa_sig.is_empty() {
        // Signature is present - verify it
        let canonical_bytes = CanonicalHeader::serialize(&hdr)?;
        
        if let Some(sig_metadata) = &hdr.signature_metadata {
            let public_key_bytes = general_purpose::STANDARD
                .decode(&sig_metadata.public_key)
                .map_err(|e| anyhow::anyhow!("Invalid public key base64: {}", e))?;
            
            // Verify signature
            let signature_valid = verify_signature(&canonical_bytes, &hdr.mldsa_sig, &public_key_bytes)?;
            if !signature_valid {
                return Err(anyhow::anyhow!("❌ ML-DSA-87 signature verification failed"));
            }
            
            // Check trust store unless --trust-any-signer is specified
            if !ctx.trust_any_signer {
                let trust_store = TrustStore::load_from_file(default_trustdb_path()?)?;
                if !trust_store.is_trusted(&sig_metadata.signer_id) {
                    return Err(anyhow::anyhow!(
                        "❌ Signer not trusted: {} (use 'qsfs trust add' or --trust-any-signer)", 
                        sig_metadata.signer_id
                    ));
                }
            }
            
            eprintln!("✅ ML-DSA-87 signature verified: {}", sig_metadata.signer_id);
        } else {
            return Err(anyhow::anyhow!("❌ Signature present but metadata missing"));
        }
    } else {
        // No signature present
        if !ctx.allow_unsigned {
            return Err(anyhow::anyhow!(
                "❌ File is not signed. Use --allow-unsigned to decrypt unsigned files (security risk)"
            ));
        }
        eprintln!("⚠️  Processing unsigned file (--allow-unsigned specified)");
    }

    // 3) Try to decrypt CEK with our key (verifiable decapsulation)
    let mut cek_bytes = None;
    for rec in &hdr.recipients {
        if let Ok(ct) = pqcrypto_mlkem::mlkem1024::Ciphertext::from_bytes(&rec.mlkem_ct) {
            let ss = mlkem::decapsulate(&ct, ctx.mlkem_sk);
            #[cfg(feature="hybrid-x25519")]
            {
                if let Some(xsk) = ctx.x25519_sk {
                    let recip_x_sk = x25519_dalek::StaticSecret::from(xsk);
                    let eph_x_pk = x25519_dalek::PublicKey::from(hdr.eph_x25519_pk);
                    let x_ss = recip_x_sk.diffie_hellman(&eph_x_pk);
                    let kek = derive_kek(ss.as_bytes(), x_ss.as_bytes(), hdr.kdf_salt.as_ref().map(|s| s.as_slice()));
                    if rec.wrapped_dek.len() == 48 {
                        if let Ok(cek) = unwrap_dek(&kek, &rec.wrap_nonce, &rec.wrapped_dek) {
                            cek_bytes = Some((cek, b"qsfs_confirm_v2".to_vec()));
                            break;
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!("X25519 secret required for hybrid decrypt"));
                }
            }
            #[cfg(not(feature="hybrid-x25519"))]
            {
                // Non-hybrid: use KEK derived from ML-KEM SS and unwrap via AES-GCM
                let kek = derive_kek(ss.as_bytes(), &[], hdr.kdf_salt.as_ref().map(|s| s.as_slice()));
                if rec.wrapped_dek.len() == 48 {
                    if let Ok(cek) = unwrap_dek(&kek, &rec.wrap_nonce, &rec.wrapped_dek) {
                        cek_bytes = Some((cek, b"qsfs_confirm_v2".to_vec()));
                        break;
                    }
                }
            }
        }
    }
    
    let (cek, confirm) = cek_bytes.ok_or_else(|| anyhow::anyhow!("No matching recipient key"))?;
    
    // 4) Derive keys from CEK
    let keys = hkdf_expand_keys(&cek, Some(&confirm));
    
    // 5) Atomic write: use temporary file with secure permissions
    let output_dir = Path::new(output_path).parent().unwrap_or(Path::new("."));
    let mut temp_file = NamedTempFile::new_in(output_dir)?;
    
    // Set secure permissions on temporary file
    set_secure_permissions(temp_file.path()).ok();
    
    let aad = hdr.aead_aad();
    let mut rest = input;
    streaming::decrypt_stream(&mut rest, temp_file.as_file_mut(), hdr.file_id, &aad,
        keys.aes_k1.expose_secret(),
        None,
    ).await?;

    // Ensure data is written to disk before atomic rename
    temp_file.as_file_mut().sync_all()?;
    
    // Atomic rename
    temp_file.persist(output_path)?;
    
    Ok(())
}
