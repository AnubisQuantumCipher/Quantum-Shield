use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as SivNonce};
use hex_literal::hex;

use qsfs_core::pae::pae_v2_compat;
use qsfs_core::suite::SuiteId;
use qsfs_core::Header;
use qsfs_core::derivation::derive_kek;

#[test]
fn kat_pae_bytes() {
    // AAD from docs/CRYPTO-SPEC-v2.md
    let file_id = hex!("8eaf015d9b2c1528");
    let chunk_size: u32 = 131072; // 0x00020000
    let mut hdr = Header {
        magic: *b"QSFS2\0",
        chunk_size,
        file_id,
        blake3_of_plain: [0u8; 32],
        suite: SuiteId::Aes256GcmSiv,
        kdf_salt: None, // v2.0 layout
        recipients: vec![],
        eph_x25519_pk: [0u8;32],
        mldsa_sig: vec![],
        ed25519_sig: vec![],
        signature_metadata: None,
        fin: 1,
    };
    let aad = pae_v2_compat(&hdr);
    let expected = hex!(
        "515346532d50414501"
        "0000000000000007"  // len("qsfs/v2")
        "717366732f7632"    // "qsfs/v2"
        "000000000000000e"  // len("aes256-gcm-siv")
        "6165733235362d67636d2d736976" // "aes256-gcm-siv"
        "0000000000000004"  // len(u32 chunk_size)
        "00020000"          // 131072
        "0000000000000008"  // len(file_id)
        "8eaf015d9b2c1528"  // file_id
    );
    assert_eq!(aad, expected, "PAE/AAD mismatch");
}

#[test]
fn kat_kek_and_wrap() {
    // KEK derivation inputs
    let mlkem_ss = hex!(
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"
    );
    let x25519_ss = hex!(
        "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
    );
    let kek = derive_kek(&mlkem_ss, &x25519_ss, None);
    let kek_expected = hex!(
        "b48776ae06e112d1115e002a687cb49b692e585eb37edb36e9ae3b2e1ddcee12"
    );
    assert_eq!(kek, kek_expected, "KEK mismatch");

    // CEK wrap under AES-256-GCM with fixed nonce
    let cek = hex!(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    );
    let nonce = hex!("000102030405060708090a0b");
    let gcm = Aes256Gcm::new_from_slice(&kek).unwrap();
    let ct = gcm
        .encrypt(GcmNonce::from_slice(&nonce), cek.as_slice())
        .expect("wrap cek");
    let ct_expected = hex!(
        "d0e68aa6ff9640c38b95c05c35314c53a3273536904bf2463ea70edb7ddcf229"
        "4890bdc7ccb2d1026d85c49e8d52d505"
    );
    assert_eq!(ct, ct_expected, "wrapped CEK mismatch");
}

#[test]
fn kat_chunk0_gcm_siv() {
    // One-chunk encrypt with SIV using known K1 and PAE from spec
    let k1 = hex!(
        "43a364585e3dd38530f880a1286aa437cb9d22e3cfa636fafdf416fbbc434342"
    );
    let file_id = hex!("8eaf015d9b2c1528");
    let mut hdr = Header {
        magic: *b"QSFS2\0",
        chunk_size: 131072u32,
        file_id,
        blake3_of_plain: [0u8; 32],
        suite: SuiteId::Aes256GcmSiv,
        kdf_salt: None,
        recipients: vec![],
        eph_x25519_pk: [0u8;32],
        mldsa_sig: vec![],
        ed25519_sig: vec![],
        signature_metadata: None,
        fin: 1,
    };
    let aad = pae_v2_compat(&hdr);
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&file_id);
    nonce[8..].copy_from_slice(&0u32.to_be_bytes());
    let siv = Aes256GcmSiv::new_from_slice(&k1).unwrap();
    let pt = b"hello qsfs v2\n";
    let ct = siv
        .encrypt(SivNonce::from_slice(&nonce), aead::Payload { msg: pt, aad: &aad })
        .expect("siv enc");
    let ct_expected = hex!(
        "9e07a7e2ba36c2d0f050d9575fd40b19c4ab226290ced7cd3851140476ad"
    );
    assert_eq!(ct, ct_expected, "chunk0 SIV ciphertext mismatch");
}
