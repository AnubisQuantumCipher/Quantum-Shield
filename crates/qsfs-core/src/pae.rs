use crate::suite::SuiteId;
use crate::header::Header;

/// QSFS v2 Pre-Authenticated Encoding (PAE):
/// AAD = "QSFS-PAE\x01" || Σ ( u64_be(len_i) || item_i )
/// items: "qsfs/v2", suite_id (ascii), u32_be(chunk_size), file_id(8b)
/// v2.0 layout (no salt)
fn pae_v2_no_salt(suite: SuiteId, chunk_size: u32, file_id: [u8; 8]) -> Vec<u8> {
    let suite_bytes = suite.as_str().as_bytes();
    let items: [&[u8]; 4] = [b"qsfs/v2", suite_bytes, &chunk_size.to_be_bytes(), &file_id];
    let mut out = Vec::with_capacity(b"QSFS-PAE\x01".len() + items.iter().map(|x| 8 + x.len()).sum::<usize>());
    out.extend_from_slice(b"QSFS-PAE\x01");
    for it in items {
        out.extend_from_slice(&(it.len() as u64).to_be_bytes());
        out.extend_from_slice(it);
    }
    out
}

/// v2.1 layout (+ 32-byte kdf_salt)
fn pae_v2_with_salt(suite: SuiteId, chunk_size: u32, file_id: [u8; 8], kdf_salt: [u8; 32]) -> Vec<u8> {
    let suite_bytes = suite.as_str().as_bytes();
    let items: [&[u8]; 5] = [b"qsfs/v2", suite_bytes, &chunk_size.to_be_bytes(), &file_id, &kdf_salt];
    let mut out = Vec::with_capacity(b"QSFS-PAE\x02".len() + items.iter().map(|x| 8 + x.len()).sum::<usize>());
    out.extend_from_slice(b"QSFS-PAE\x02");
    for it in items {
        out.extend_from_slice(&(it.len() as u64).to_be_bytes());
        out.extend_from_slice(it);
    }
    out
}

/// Backward-compatible PAE builder used by Header::aead_aad()
pub fn pae_v2_compat(h: &Header) -> Vec<u8> {
    match h.kdf_salt {
        Some(s) => pae_v2_with_salt(h.suite, h.chunk_size, h.file_id, s),
        None => pae_v2_no_salt(h.suite, h.chunk_size, h.file_id),
    }
}
