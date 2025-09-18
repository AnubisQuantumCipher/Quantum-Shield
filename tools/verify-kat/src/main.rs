use aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as N12};
use hkdf::Hkdf;
use serde::Deserialize;
use sha3::Sha3_384;

#[derive(Deserialize)]
#[allow(dead_code)]
struct Kat {
    version: String,
    suite: String,
    chunk_size: u32,
    file_id_hex: String,
    kdf_salt_hex: Option<String>,
    aad_hex: String,
    hkdf: HkdfKat,
    wrap: WrapKat,
    chunk0_siv: ChunkSivKat,
}

#[derive(Deserialize)]
struct HkdfKat {
    hash: String,
    extract_salt: String,
    info: String,
    mlkem_ss_hex: String,
    x25519_ss_hex: String,
    kek_hex: String,
}

#[derive(Deserialize)]
struct WrapKat {
    alg: String,
    nonce_hex: String,
    cek_hex: String,
    wrapped_hex: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ChunkSivKat {
    pt_utf8: String,
    ct_hex: String,
}

fn hex_to<const N: usize>(s: &str) -> [u8; N] {
    let v = hex::decode(s).expect("hex");
    assert_eq!(v.len(), N);
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: verify-kat file.json");
    let data = std::fs::read_to_string(path)?;
    let kat: Kat = serde_json::from_str(&data)?;

    // Rebuild AAD per spec
    let aad_expected = hex::decode(&kat.aad_hex)?;
    let suite_ascii = kat.suite.as_bytes();
    let mut aad = Vec::new();
    let prefix = if kat.kdf_salt_hex.is_some() { b"QSFS-PAE\x02" } else { b"QSFS-PAE\x01" };
    aad.extend_from_slice(prefix);
    let mut items: Vec<Vec<u8>> = vec![
        b"qsfs/v2".to_vec(),
        suite_ascii.to_vec(),
        kat.chunk_size.to_be_bytes().to_vec(),
        hex::decode(&kat.file_id_hex)?,
    ];
    if let Some(s) = &kat.kdf_salt_hex { items.push(hex::decode(s)?); }
    for it in items { aad.extend_from_slice(&(it.len() as u64).to_be_bytes()); aad.extend_from_slice(&it); }
    if aad != aad_expected { anyhow::bail!("AAD mismatch"); }

    // HKDF (SHA3-384)
    assert_eq!(kat.hkdf.hash, "sha3-384");
    assert_eq!(kat.hkdf.info, "qsfs/kek/v2");
    let mut ikm = hex::decode(&kat.hkdf.mlkem_ss_hex)?;
    let x = hex::decode(&kat.hkdf.x25519_ss_hex).unwrap_or_default();
    ikm.extend_from_slice(&x);
    let salt_bytes = if let Some(s) = &kat.kdf_salt_hex {
        hex::decode(s)?
    } else {
        kat.hkdf.extract_salt.as_bytes().to_vec()
    };
    let hk = Hkdf::<Sha3_384>::new(Some(&salt_bytes), &ikm);
    let mut kek = [0u8; 32];
    hk.expand(b"qsfs/kek/v2", &mut kek).expect("expand");
    let kek_expected = hex_to::<32>(&kat.hkdf.kek_hex);
    if kek != kek_expected { anyhow::bail!("KEK mismatch"); }

    // Wrap check (AES-256-GCM)
    assert_eq!(kat.wrap.alg, "aes256-gcm");
    let nonce_bytes = hex_to::<12>(&kat.wrap.nonce_hex);
    let nonce = N12::from_slice(&nonce_bytes);
    let cek = hex::decode(&kat.wrap.cek_hex)?;
    let wrapped_expected = hex::decode(&kat.wrap.wrapped_hex)?;
    let aead_gcm = Aes256Gcm::new_from_slice(&kek).unwrap();
    let wrapped = aead_gcm.encrypt(nonce, cek.as_slice()).expect("wrap");
    if wrapped != wrapped_expected { anyhow::bail!("Wrapped CEK mismatch"); }

    // Optionally verify SIV chunk if k1 published (not in this KAT)
    // let k1 = hex_to::<32>(&kat.stream_k1_hex);
    // let nonce0 = { let mut n=[0u8;12]; n[..8].copy_from_slice(&hex::decode(&kat.file_id_hex)?); n[8..].copy_from_slice(&0u32.to_be_bytes()); N12::from_slice(&n) };
    // let aead_siv = Aes256GcmSiv::new_from_slice(&k1).unwrap();
    // let got = aead_siv.encrypt(nonce0, aead::Payload{ msg: kat.chunk0_siv.pt_utf8.as_bytes(), aad: &aad }).unwrap();
    // assert_eq!(got, hex::decode(&kat.chunk0_siv.ct_hex)?, "SIV chunk ct mismatch");

    println!("KAT OK");
    Ok(())
}
