use anyhow::Result;
use pqcrypto_mlkem::mlkem1024::*;
use pqcrypto_traits::kem::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait};

fn main() -> Result<()> {
    let (pk, sk) = keypair();
    std::fs::write("mlkem1024.pk", pk.as_bytes())?;
    std::fs::write("mlkem1024.sk", sk.as_bytes())?;
    eprintln!("wrote mlkem1024.pk, mlkem1024.sk");
    Ok(())
}

