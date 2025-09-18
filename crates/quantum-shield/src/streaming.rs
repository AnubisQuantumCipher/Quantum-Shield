use aead::{Aead, KeyInit};
// AEAD selection with feature gating: default AES-GCM-SIV, optional AES-GCM
#[cfg(feature = "gcm-siv")]
use aes_gcm_siv::{Aes256GcmSiv as Aes, Nonce as GcmNonce};
#[cfg(all(not(feature = "gcm-siv"), feature = "gcm"))]
use aes_gcm::{Aes256Gcm as Aes, Nonce as GcmNonce};
#[cfg(all(not(feature = "gcm-siv"), not(feature = "gcm")))]
compile_error!("Enable either 'gcm-siv' (default) or 'gcm' feature");
#[cfg(feature="cascade")]
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChNonce};
use anyhow::{Result, bail};
use tokio::{fs::File, io::AsyncReadExt};
use std::io::Write;
use zeroize::Zeroize;

const MAX_CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB max
const MAX_CHUNKS: u64 = 1 << 32; // 4 billion chunks max

/// Derive 96‑bit nonce from 64‑bit file_id seed and 32‑bit chunk counter.
fn nonce_96(file_id: [u8;8], chunk_no: u32) -> [u8;12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&file_id);
    n[8..].copy_from_slice(&chunk_no.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_uniqueness_within_file() {
        let file_id = [1u8,2,3,4,5,6,7,8];
        let n0 = nonce_96(file_id, 0);
        let n1 = nonce_96(file_id, 1);
        assert_ne!(n0, n1);
    }

    #[test]
    fn test_nonce_uniqueness_across_files() {
        let f1 = [1u8,2,3,4,5,6,7,8];
        let f2 = [8u8,7,6,5,4,3,2,1];
        let n_a = nonce_96(f1, 42);
        let n_b = nonce_96(f2, 42);
        assert_ne!(n_a, n_b);
    }
}

/// Encrypt in streaming mode with enhanced security
#[allow(unused_variables)]
pub async fn encrypt_stream(
    in_path: &str,
    out: &mut std::fs::File,
    chunk_size: usize,
    file_id: [u8;8],
    aad: &[u8],
    k1_aes: &[u8;32],
    k2_chacha: Option<&[u8;32]>,
) -> Result<()> {
    // Validate chunk size
    if chunk_size > MAX_CHUNK_SIZE {
        bail!("Chunk size too large: {} > {}", chunk_size, MAX_CHUNK_SIZE);
    }
    
    let aes = Aes::new_from_slice(k1_aes).unwrap();
    #[cfg(feature="cascade")]
    let ch = k2_chacha.map(|k| ChaCha20Poly1305::new_from_slice(k).unwrap());

    let mut f = File::open(in_path).await?;
    let mut buf = vec![0u8; chunk_size];
    let mut chunk_no: u32 = 0;
    
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 { break; }
        
        // Check for chunk overflow
        if chunk_no as u64 >= MAX_CHUNKS {
            bail!("Too many chunks: {} >= {}", chunk_no, MAX_CHUNKS);
        }
        
        let n96 = nonce_96(file_id, chunk_no);
        let pt = &buf[..n];

        #[cfg(feature="cascade")]
        let ct_inner = if let Some(ref ch) = ch {
            let n2 = ChNonce::from_slice(&n96);
            ch.encrypt(n2, pt).map_err(|_| anyhow::anyhow!("chacha seal"))?
        } else { pt.to_vec() };

        #[cfg(not(feature="cascade"))]
        let ct_inner = pt.to_vec();

        let n1 = GcmNonce::from_slice(&n96);
        let ct_outer = aes.encrypt(n1, aead::Payload { msg: &ct_inner, aad })
            .map_err(|_| anyhow::anyhow!("aes-gcm seal"))?;

        // frame: [u32 chunk_no][u32 len][bytes]
        out.write_all(&chunk_no.to_be_bytes())?;
        out.write_all(&(ct_outer.len() as u32).to_be_bytes())?;
        out.write_all(&ct_outer)?;
        
        chunk_no = chunk_no.checked_add(1).ok_or_else(|| anyhow::anyhow!("chunk overflow"))?;
        
        // Zeroize the buffer after use
        buf[..n].zeroize();
    }
    
    // Final sync
    out.sync_all()?;
    Ok(())
}

/// Decrypt counterpart with enhanced security
#[allow(unused_variables)]
pub async fn decrypt_stream(
    in_bytes: &mut (impl AsyncReadExt + Unpin),
    out: &mut std::fs::File,
    file_id: [u8;8],
    aad: &[u8],
    k1_aes: &[u8;32],
    k2_chacha: Option<&[u8;32]>,
) -> Result<()> {
    let aes = Aes::new_from_slice(k1_aes).unwrap();
    #[cfg(feature="cascade")]
    let ch = k2_chacha.map(|k| ChaCha20Poly1305::new_from_slice(k).unwrap());

    let mut expected_chunk: u32 = 0;
    let mut total_chunks: u64 = 0;
    
    loop {
        let mut hdr = [0u8; 8];
        match in_bytes.read_exact(&mut hdr).await {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        
        let chunk_no = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let len = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        
        // Validate chunk ordering and limits
        if chunk_no != expected_chunk { 
            bail!("chunk out of order: expected {}, got {}", expected_chunk, chunk_no); 
        }
        if len > MAX_CHUNK_SIZE + 16 { // +16 for AEAD tag
            bail!("chunk too large: {}", len);
        }
        if total_chunks >= MAX_CHUNKS {
            bail!("too many chunks: {}", total_chunks);
        }
        
        let mut ct = vec![0u8; len];
        in_bytes.read_exact(&mut ct).await?;

        let n96 = nonce_96(file_id, chunk_no);
        let n1 = GcmNonce::from_slice(&n96);
        let inner = aes.decrypt(n1, aead::Payload{ msg: &ct, aad })
            .map_err(|_| anyhow::anyhow!("aes-gcm tag failure at chunk {}", chunk_no))?;

        #[cfg(feature="cascade")]
        let pt = if let Some(ref ch) = ch {
            let n2 = ChNonce::from_slice(&n96);
            ch.decrypt(n2, inner.as_slice()).map_err(|_| anyhow::anyhow!("chacha tag failure at chunk {}", chunk_no))?
        } else { inner };

        #[cfg(not(feature="cascade"))]
        let pt = inner;

        out.write_all(&pt)?;
        
        expected_chunk = expected_chunk.checked_add(1).ok_or_else(|| anyhow::anyhow!("chunk overflow"))?;
        total_chunks += 1;
        
        // Zeroize sensitive data
        ct.zeroize();
    }
    
    // Final sync
    out.sync_all()?;
    Ok(())
}
