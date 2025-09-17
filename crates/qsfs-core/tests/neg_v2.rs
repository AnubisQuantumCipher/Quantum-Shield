#[cfg(feature="gcm")] use aes_gcm::{Aes256Gcm, aead::Aead, KeyInit, Nonce as N12};
#[cfg(feature="gcm-siv")] use aes_gcm_siv::{Aes256GcmSiv, aead::Aead, KeyInit, Nonce as N12};

use qsfs_core::{suite::SuiteId, pae::pae_v2_compat};
use qsfs_core::Header;

fn header_for_tests(suite: SuiteId) -> Header {
    Header {
        magic: *b"QSFS2\0",
        chunk_size: 65536,
        file_id: *b"\x8e\xaf\x01\x5d\x9b\x2c\x15\x28",
        blake3_of_plain: [0u8; 32],
        suite,
        kdf_salt: None,
        recipients: vec![],
        eph_x25519_pk: [0u8;32],
        mldsa_sig: vec![],
        ed25519_sig: vec![],
        signature_metadata: None,
        fin: 1,
    }
}

#[cfg(feature="gcm-siv")]
#[test]
fn aad_tamper_fails_under_siv() {
    let hdr = header_for_tests(SuiteId::Aes256GcmSiv);
    let aad = pae_v2_compat(&hdr);
    let k = [0u8; 32];
    let aead = Aes256GcmSiv::new_from_slice(&k).unwrap();
    let nonce = N12::from_slice(&[0u8;12]);
    let pt = b"hello qsfs v2\n";
    let ct = aead.encrypt(nonce, aead::Payload { msg: pt, aad: &aad }).unwrap();

    // Tamper AAD by changing the suite
    let mut hdr2 = hdr.clone();
    hdr2.suite = SuiteId::Aes256Gcm; // tamper
    let tampered_aad = pae_v2_compat(&hdr2);
    let res = aead.decrypt(nonce, aead::Payload { msg: &ct, aad: &tampered_aad });
    assert!(res.is_err(), "tampering AAD must fail decryption");
}

#[cfg(feature="gcm")]
#[test]
fn nonce_reuse_under_gcm_leaks_xor_relation() {
    // Demonstrate classic GCM nonce-reuse leakage
    let k = [1u8; 32];
    let aead = Aes256Gcm::new_from_slice(&k).unwrap();
    let n = N12::from_slice(&[9u8;12]);
    let aad = b"demo-aad";
    let m1 = b"The quick brown fox";
    let m2 = b"Jumps over lazy dog!";
    let c1 = aead.encrypt(n, aead::Payload { msg: m1, aad }).unwrap();
    let c2 = aead.encrypt(n, aead::Payload { msg: m2, aad }).unwrap();
    let (d1, _t1) = c1.split_at(c1.len()-16);
    let (d2, _t2) = c2.split_at(c2.len()-16);
    let xr_ct: Vec<u8> = d1.iter().zip(d2).map(|(a,b)| a ^ b).collect();
    let xr_pt: Vec<u8> = m1.iter().zip(m2).map(|(a,b)| a ^ b).collect();
    assert_eq!(xr_ct, xr_pt, "GCM nonce reuse reveals XOR(m1,m2)");
}

#[test]
fn wrap_tamper_fails() {
    use aes_gcm::{Aes256Gcm, aead::Aead as _, KeyInit};
    let kek = [7u8; 32];
    let wrap_nonce = [0u8; 12];
    let cek = [3u8; 32];
    let aead = Aes256Gcm::new_from_slice(&kek).unwrap();
    let ct = aead.encrypt(N12::from_slice(&wrap_nonce), cek.as_slice()).unwrap();
    let mut bad = ct.clone();
    bad[0] ^= 0x80;
    let res = aead.decrypt(N12::from_slice(&wrap_nonce), bad.as_slice());
    assert!(res.is_err(), "Tampered wrapped CEK must fail to unwrap");
}
