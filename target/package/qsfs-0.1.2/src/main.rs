use clap::{Parser, Subcommand};
use anyhow::Result;
use qsfs_core::{seal, SealRequest, unseal, UnsealContext, signer};
use tokio::fs::File;
use pqcrypto_traits::kem::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};
use pqcrypto_traits::sign::PublicKey as SignPublicKeyTrait;
use base64::{engine::general_purpose, Engine as _};

#[derive(Parser, Debug)]
#[command(author, version, about="QSFS: Quantum‑Shield File Encryption System (PQ‑first with ML-DSA-87 signatures)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Encrypt a file with quantum-resistant encryption and ML-DSA-87 signature (always signed)
    Encrypt {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        /// Path(s) to ML‑KEM‑1024 public key (raw pqcrypto bytes)
        #[arg(long = "recipient-pk", num_args=1.., required=true)]
        recipient_pk: Vec<String>,
        /// Path(s) to X25519 public key (32-byte raw)
        #[cfg(feature = "hybrid-x25519")]
        #[arg(long = "recipient-x25519-pk", num_args=1.., required=true)]
        recipient_x25519_pk: Vec<String>,
        /// (non-hybrid builds) Optional X25519 keys are ignored
        #[cfg(not(feature = "hybrid-x25519"))]
        #[arg(long = "recipient-x25519-pk", num_args=0.., required=false)]
        recipient_x25519_pk: Vec<String>,
        #[arg(long, default_value_t=131072)]
        chunk: usize,
        #[arg(long)]
        explain: bool,
        /// Use specific signer key file
        #[arg(long)]
        signer_key: Option<String>,
    },
    /// Generate an X25519 keypair (32-byte raw files)
    X25519Keygen {
        /// Output directory (default: $HOME/.qsfs)
        #[arg(short, long)]
        outdir: Option<String>,
    },
    /// Inspect header fields without decrypting
    Inspect {
        /// Input .qsfs file
        input: String,
    },
    /// Decrypt and verify a quantum-encrypted file (signature required and must be trusted)
    Decrypt {
        #[arg(long)]
        input: String,
        #[arg(long)]
        output: String,
        #[arg(long = "mlkem-sk")]
        mlkem_sk: String,
        /// X25519 secret key (32-byte raw)
        #[cfg(feature = "hybrid-x25519")]
        #[arg(long = "x25519-sk")]
        x25519_sk: Option<String>,
        #[cfg(not(feature = "hybrid-x25519"))]
        #[arg(long = "x25519-sk")]
        x25519_sk: Option<String>,
        // No weak-privacy flags; signatures are enforced by default
    },
    /// Generate ML-DSA-87 signer key pair
    SignerKeygen {
        /// Output signer key file (default: auto-provision)
        #[arg(short, long)]
        output: Option<String>,
        /// Encrypt signer with passphrase (read from env QSFS_SIGNER_PASSPHRASE or prompt disabled)
        #[arg(long)]
        encrypt: bool,
    },
    /// Trust store management
    Trust {
        #[command(subcommand)]
        action: TrustAction,
    },
}

#[derive(Subcommand, Debug)]
enum TrustAction {
    /// Add a signer to the trust store
    Add {
        /// Public key file to trust
        pubkey_file: String,
        /// Note about this signer
        #[arg(short, long)]
        note: Option<String>,
    },
    /// List trusted signers
    List,
    /// Remove a signer from trust store
    Remove {
        /// Signer ID to remove
        signer_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encrypt { input, output, recipient_pk, recipient_x25519_pk, chunk, explain, signer_key } => {
            let mut recs = Vec::new();
            #[cfg(feature = "hybrid-x25519")]
            if recipient_pk.len() != recipient_x25519_pk.len() { anyhow::bail!("number of ML-KEM and X25519 keys must match"); }
            
            #[cfg(feature = "hybrid-x25519")]
            for (p_mlkem, p_x) in recipient_pk.into_iter().zip(recipient_x25519_pk.into_iter()) {
                let bytes = tokio::fs::read(p_mlkem).await?;
                let pk = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(&bytes)?;
                let xbytes = tokio::fs::read(p_x).await?;
                if xbytes.len() != 32 { anyhow::bail!("X25519 public key must be 32 bytes"); }
                let mut xarr = [0u8;32]; xarr.copy_from_slice(&xbytes);
                recs.push( (String::from("recipient"), pk, xarr) );
            }
            
            #[cfg(not(feature = "hybrid-x25519"))]
            for p_mlkem in recipient_pk.into_iter() {
                let bytes = tokio::fs::read(p_mlkem).await?;
                let pk = pqcrypto_mlkem::mlkem1024::PublicKey::from_bytes(&bytes)?;
                recs.push( (String::from("recipient"), pk, [0u8;32]) );
            }
            
            // Always sign: load provided signer or auto-provision one
            let signer_val = if let Some(signer_path) = signer_key {
                signer::Signer::load_from_file(signer_path)?
            } else {
                signer::auto_provision_signer()?
            };
            
            seal(SealRequest{
                input_path: &input,
                recipients: recs,
                header_sign_mldsa_sk: Some(signer_val.sk),
                chunk_size: chunk,
                signer: Some(&signer_val),
            }, &output).await?;
            
            if explain { eprintln!("sealed -> {}\nsigned with ML-DSA-87 signer.", output); }
        }
        Cmd::Inspect { input } => {
            use std::io::Read;
            let mut f = std::fs::File::open(&input)?;
            let mut len_buf = [0u8;4];
            f.read_exact(&mut len_buf)?;
            let hdr_len = u32::from_be_bytes(len_buf) as usize;
            let mut hdr_buf = vec![0u8; hdr_len];
            f.read_exact(&mut hdr_buf)?;
            let hdr: qsfs_core::Header = postcard::from_bytes(&hdr_buf)?;

            // Invariants
            const MLKEM1024_CT_LEN: usize = 1568;
            const MLDSA87_PK_LEN: usize = 2592;
            if let Some(md) = &hdr.signature_metadata {
                let pk = general_purpose::STANDARD.decode(&md.public_key)
                    .map_err(|_| anyhow::anyhow!("invalid base64 sender pk"))?;
                if pk.len() != MLDSA87_PK_LEN { anyhow::bail!("invalid ML-DSA-87 public key length: {}", pk.len()); }
            }
            #[cfg(feature = "hybrid-x25519")]
            if hdr.eph_x25519_pk == [0u8;32] { anyhow::bail!("missing ephemeral X25519 public key (hybrid required)"); }
            for (i, r) in hdr.recipients.iter().enumerate() {
                if r.mlkem_ct.len() != MLKEM1024_CT_LEN { anyhow::bail!("recipient[{i}]: bad ML-KEM-1024 ct length {}", r.mlkem_ct.len()); }
                let wrap_len = if !r.wrapped_dek.is_empty() { r.wrapped_dek.len() } else { r.wrap.len() };
                if wrap_len != 48 { anyhow::bail!("recipient[{i}]: wrapped_dek must be 48 bytes (AES-GCM 32+16), got {wrap_len}"); }
            }

            let has_sig = !hdr.mldsa_sig.is_empty();
            let has_x25519 = hdr.eph_x25519_pk != [0u8;32] || hdr.recipients.iter().any(|r| !r.x25519_pub.is_empty());
            let mut suite = format!("{} + ML-KEM-1024",
                hdr.suite.as_str().replace('-', "/").to_uppercase().replace("AES256/","AES-256-")
            );
            if has_sig { suite.push_str(" + ML-DSA-87"); }
            if has_x25519 { suite.push_str(" (+X25519)"); }

            let sender_pk_len = hdr.signature_metadata.as_ref().and_then(|m| {
                general_purpose::STANDARD.decode(&m.public_key).ok().map(|b| b.len())
            });

            println!("File: {}", input);
            println!("Suite: {}", suite);
            println!("Chunk size: {}", hdr.chunk_size);
            println!("AEAD suite: {}", hdr.suite.as_str());
            println!("KDF: HKDF(SHA3-384)");
            match hdr.kdf_salt {
                Some(s) => println!("kdf_salt: {} (v2.1; bound in AAD)", hex::encode(s)),
                None => println!("kdf_salt: <none> (v2.0; salt=\"qsfs/kdf/v2\")"),
            }
            println!("Recipients: {}", hdr.recipients.len());
            for (i, r) in hdr.recipients.iter().enumerate() {
                let wrap_len = r.wrapped_dek.len();
                println!(
                    "  [{}] label='{}' ct_len={} wrap_len={} x25519_len={}",
                    i,
                    r.label,
                    r.mlkem_ct.len(),
                    wrap_len,
                    r.x25519_pub.len()
                );
            }
            if let Some(pk_len) = sender_pk_len { println!("Signer PK length: {} bytes", pk_len); }
            println!("FIN: {}", hdr.fin);
        }
        Cmd::Decrypt { input, output, mlkem_sk, x25519_sk } => {
            // No weak-privacy flags; signatures are enforced by default
            let inp = File::open(&input).await?;
            let sk_bytes = tokio::fs::read(mlkem_sk).await?;
            let sk = pqcrypto_mlkem::mlkem1024::SecretKey::from_bytes(&sk_bytes)?;
            let xsk_opt = if let Some(p) = x25519_sk { 
                let b = tokio::fs::read(p).await?; 
                if b.len()!=32 { anyhow::bail!("X25519 secret key must be 32 bytes"); }
                let mut arr=[0u8;32]; arr.copy_from_slice(&b); Some(arr)
            } else { None };
            
            unseal(inp, &output, UnsealContext{ 
                mlkem_sk: &sk,
                x25519_sk: xsk_opt,
                allow_unsigned: false,
                trust_any_signer: false,
            }).await?;
        }
        Cmd::SignerKeygen { output, encrypt } => {
            let signer = signer::Signer::generate()?;
            let path = if let Some(ref p) = output {
                std::path::PathBuf::from(p)
            } else {
                signer::default_signer_path()?
            };
            
            if encrypt || std::env::var("QSFS_SIGNER_PASSPHRASE").is_ok() {
                signer.save_to_file_encrypted(&path)?;
            } else {
                signer.save_to_file(&path)?;
            }
            println!("Generated ML-DSA-87 signer: {}", signer.id_hex());
            println!("Saved to: {}", path.display());
            
            // Add to trust store if using default path
            if output.is_none() {
                let trustdb_path = signer::default_trustdb_path()?;
                let mut trust_store = signer::TrustStore::load_from_file(&trustdb_path)?;
                trust_store.add_signer(
                    signer.id_hex(),
                    signer.public_key_base64(),
                    "Self-generated signer".to_string(),
                )?;
                trust_store.save_to_file(&trustdb_path)?;
                println!("Added to trust store");
            }
        }
        Cmd::Trust { action } => {
            match action {
                TrustAction::Add { pubkey_file, note } => {
                    let pubkey_bytes = std::fs::read(pubkey_file)?;
                    let pubkey = pqcrypto_mldsa::mldsa87::PublicKey::from_bytes(&pubkey_bytes)
                        .map_err(|_| anyhow::anyhow!("Invalid public key format"))?;
                    
                    // Calculate signer ID
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(pubkey.as_bytes());
                    let signer_id = hex::encode(hasher.finalize());
                    
                    let mut trust_store = signer::TrustStore::load_from_file(signer::default_trustdb_path()?)?;
                    trust_store.add_signer(
                        signer_id.clone(),
                        general_purpose::STANDARD.encode(pubkey.as_bytes()),
                        note.unwrap_or_else(|| "Manually added".to_string()),
                    )?;
                    trust_store.save_to_file(signer::default_trustdb_path()?)?;
                    
                    println!("✅ Added signer to trust store: {}", signer_id);
                },
                TrustAction::List => {
                    let trust_store = signer::TrustStore::load_from_file(signer::default_trustdb_path()?)?;
                    let signers = trust_store.list_signers();
                    
                    if signers.is_empty() {
                        println!("No trusted signers found.");
                    } else {
                        println!("Trusted signers:");
                        for entry in signers {
                            println!("  ID: {}", entry.signer_id);
                            println!("  Note: {}", entry.note);
                            println!("  Added: {}", chrono::DateTime::from_timestamp(entry.added_at as i64, 0)
                                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                                .unwrap_or_else(|| "Unknown".to_string()));
                            println!();
                        }
                    }
                },
                TrustAction::Remove { signer_id } => {
                    let mut trust_store = signer::TrustStore::load_from_file(signer::default_trustdb_path()?)?;
                    if trust_store.remove_signer(&signer_id) {
                        trust_store.save_to_file(signer::default_trustdb_path()?)?;
                        println!("✅ Removed signer from trust store: {}", signer_id);
                    } else {
                        println!("❌ Signer not found in trust store: {}", signer_id);
                    }
                },
            }
        }
        Cmd::X25519Keygen { outdir } => {
            let rng = rand::rngs::OsRng;
            let sk = x25519_dalek::StaticSecret::random_from_rng(rng);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let dir = if let Some(d) = outdir { std::path::PathBuf::from(d) } else { 
                let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no home dir"))?;
                home.join(".qsfs")
            };
            std::fs::create_dir_all(&dir)?;
            let pk_path = dir.join("x25519.pk");
            let sk_path = dir.join("x25519.sk");
            std::fs::write(&pk_path, pk.as_bytes())?;
            std::fs::write(&sk_path, sk.to_bytes())?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600))?;
            }
            println!("Wrote X25519 public key: {}", pk_path.display());
            println!("Wrote X25519 secret key: {}", sk_path.display());
        }
    }
    Ok(())
}
