#!/usr/bin/env python3
import json, sys, binascii, struct, hmac, hashlib

try:
    from Cryptodome.Cipher import AES  # pip install pycryptodome
except Exception:
    AES = None

def hkdf_sha3_384(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    # RFC5869 using SHA3-384
    prk = hmac.new(salt, ikm, hashlib.sha3_384).digest() if salt else hashlib.sha3_384(ikm).digest()
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha3_384).digest()
        okm += t
        counter += 1
    return okm[:length]

def pae(prefix: bytes, items: list[bytes]) -> bytes:
    out = bytearray(prefix)
    for it in items:
        out += struct.pack(">Q", len(it)) + it
    return bytes(out)

def hex2b(s: str) -> bytes:
    return binascii.unhexlify(s)

def main(path: str):
    kat = json.load(open(path, "r"))

    version = kat["version"]
    suite   = kat["suite"].encode()
    chunk_size = kat["chunk_size"]
    file_id = hex2b(kat["file_id_hex"])
    kdf_salt = hex2b(kat["kdf_salt_hex"]) if kat["kdf_salt_hex"] else None

    prefix = b"QSFS-PAE\x02" if kdf_salt else b"QSFS-PAE\x01"
    items  = [b"qsfs/v2", suite, chunk_size.to_bytes(4, "big"), file_id]
    if kdf_salt: items.append(kdf_salt)
    aad = pae(prefix, items)
    assert aad.hex() == kat["aad_hex"].lower(), "AAD mismatch"

    hk = kat["hkdf"]
    assert hk["hash"] == "sha3-384" and hk["info"] == "qsfs/kek/v2"
    mlkem = hex2b(hk["mlkem_ss_hex"])
    x25519 = hex2b(hk["x25519_ss_hex"]) if hk["x25519_ss_hex"] else b""
    ikm = mlkem + x25519
    salt = kdf_salt if kdf_salt else hk["extract_salt"].encode()
    kek = hkdf_sha3_384(ikm, salt, b"qsfs/kek/v2", 32)
    assert kek.hex() == hk["kek_hex"].lower(), "KEK mismatch"

    if AES:
        wrap = kat["wrap"]
        assert wrap["alg"] == "aes256-gcm"
        nonce = hex2b(wrap["nonce_hex"])
        cek   = hex2b(wrap["cek_hex"])
        exp   = hex2b(wrap["wrapped_hex"])
        cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
        ctext, tag = cipher.encrypt_and_digest(cek)
        got = ctext + tag
        assert got == exp, "Wrapped CEK mismatch"
    else:
        print("NOTE: PyCryptodome not available; skipping AES-GCM wrap check")

    print("KAT OK")

if __name__ == "__main__":
    main(sys.argv[1])

