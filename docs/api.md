# Quantum Shield API Reference

## Overview

The Quantum Shield API provides comprehensive access to quantum-safe cryptographic operations, certificate management, and trust store functionality. This document covers all available APIs, including REST endpoints, library interfaces, and integration examples.

## Library API

### Core Cryptographic Operations

#### Key Generation

```rust
use quantum_shield::{
    crypto::{KeyPair, Algorithm, SecurityLevel},
    error::QuantumShieldError,
};

/// Generate a new key pair for the specified algorithm
pub fn generate_key_pair(
    algorithm: Algorithm,
    security_level: SecurityLevel,
) -> Result<KeyPair, QuantumShieldError> {
    match algorithm {
        Algorithm::MlDsa => {
            let params = match security_level {
                SecurityLevel::Level1 => MlDsaParameterSet::ML_DSA_44,
                SecurityLevel::Level3 => MlDsaParameterSet::ML_DSA_65,
                SecurityLevel::Level5 => MlDsaParameterSet::ML_DSA_87,
            };
            Ok(KeyPair::MlDsa(MlDsaKeyPair::generate(params)?))
        },
        Algorithm::MlKem => {
            let params = match security_level {
                SecurityLevel::Level1 => MlKemParameterSet::ML_KEM_512,
                SecurityLevel::Level3 => MlKemParameterSet::ML_KEM_768,
                SecurityLevel::Level5 => MlKemParameterSet::ML_KEM_1024,
            };
            Ok(KeyPair::MlKem(MlKemKeyPair::generate(params)?))
        },
        Algorithm::Falcon => {
            let params = match security_level {
                SecurityLevel::Level1 => FalconParameterSet::Falcon512,
                SecurityLevel::Level5 => FalconParameterSet::Falcon1024,
                _ => return Err(QuantumShieldError::UnsupportedSecurityLevel),
            };
            Ok(KeyPair::Falcon(FalconKeyPair::generate(params)?))
        },
        Algorithm::SphincsPlus => {
            let params = match security_level {
                SecurityLevel::Level1 => SphincsParameterSet::SphincsShake128f,
                SecurityLevel::Level3 => SphincsParameterSet::SphincsShake192f,
                SecurityLevel::Level5 => SphincsParameterSet::SphincsShake256f,
            };
            Ok(KeyPair::SphincsPlus(SphincsKeyPair::generate(params)?))
        },
        Algorithm::Ed25519 => {
            Ok(KeyPair::Ed25519(Ed25519KeyPair::generate()?))
        },
        Algorithm::X25519 => {
            Ok(KeyPair::X25519(X25519KeyPair::generate()?))
        },
        Algorithm::Hybrid => {
            Ok(KeyPair::Hybrid(HybridKeyPair::generate(security_level)?))
        },
    }
}

/// Example usage
fn example_key_generation() -> Result<(), QuantumShieldError> {
    // Generate ML-DSA key pair for digital signatures
    let signature_keys = generate_key_pair(
        Algorithm::MlDsa,
        SecurityLevel::Level3,
    )?;
    
    // Generate ML-KEM key pair for key encapsulation
    let kem_keys = generate_key_pair(
        Algorithm::MlKem,
        SecurityLevel::Level3,
    )?;
    
    // Generate hybrid key pair combining classical and post-quantum
    let hybrid_keys = generate_key_pair(
        Algorithm::Hybrid,
        SecurityLevel::Level3,
    )?;
    
    println!("Generated key pairs successfully");
    Ok(())
}
```

#### Digital Signatures

```rust
use quantum_shield::crypto::{Signature, SignatureAlgorithm};

/// Sign data with the specified key pair
pub fn sign_data(
    data: &[u8],
    key_pair: &KeyPair,
    algorithm: SignatureAlgorithm,
) -> Result<Signature, QuantumShieldError> {
    match key_pair {
        KeyPair::MlDsa(keys) => {
            let signature = keys.sign(data)?;
            Ok(Signature::MlDsa(signature))
        },
        KeyPair::Falcon(keys) => {
            let signature = keys.sign(data)?;
            Ok(Signature::Falcon(signature))
        },
        KeyPair::SphincsPlus(keys) => {
            let signature = keys.sign(data)?;
            Ok(Signature::SphincsPlus(signature))
        },
        KeyPair::Ed25519(keys) => {
            let signature = keys.sign(data)?;
            Ok(Signature::Ed25519(signature))
        },
        KeyPair::Hybrid(keys) => {
            let signature = keys.sign(data)?;
            Ok(Signature::Hybrid(signature))
        },
        _ => Err(QuantumShieldError::InvalidKeyPairForSigning),
    }
}

/// Verify a signature
pub fn verify_signature(
    data: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool, QuantumShieldError> {
    match (signature, public_key) {
        (Signature::MlDsa(sig), PublicKey::MlDsa(pk)) => {
            pk.verify(data, sig)
        },
        (Signature::Falcon(sig), PublicKey::Falcon(pk)) => {
            pk.verify(data, sig)
        },
        (Signature::SphincsPlus(sig), PublicKey::SphincsPlus(pk)) => {
            pk.verify(data, sig)
        },
        (Signature::Ed25519(sig), PublicKey::Ed25519(pk)) => {
            pk.verify(data, sig)
        },
        (Signature::Hybrid(sig), PublicKey::Hybrid(pk)) => {
            pk.verify(data, sig)
        },
        _ => Err(QuantumShieldError::SignaturePublicKeyMismatch),
    }
}

/// Example usage
fn example_signing() -> Result<(), QuantumShieldError> {
    let message = b"Hello, Quantum World!";
    
    // Generate signing key pair
    let key_pair = generate_key_pair(Algorithm::MlDsa, SecurityLevel::Level3)?;
    
    // Sign the message
    let signature = sign_data(message, &key_pair, SignatureAlgorithm::MlDsa65)?;
    
    // Verify the signature
    let public_key = key_pair.public_key();
    let is_valid = verify_signature(message, &signature, &public_key)?;
    
    assert!(is_valid);
    println!("Signature verification successful");
    Ok(())
}
```

#### Key Encapsulation

```rust
use quantum_shield::crypto::{SharedSecret, Ciphertext};

/// Encapsulate a shared secret using KEM
pub fn encapsulate_secret(
    public_key: &PublicKey,
) -> Result<(SharedSecret, Ciphertext), QuantumShieldError> {
    match public_key {
        PublicKey::MlKem(pk) => {
            let mut rng = ChaCha20Rng::from_entropy();
            let (secret, ciphertext) = pk.encapsulate(&mut rng)?;
            Ok((SharedSecret::new(secret), Ciphertext::MlKem(ciphertext)))
        },
        PublicKey::X25519(pk) => {
            let ephemeral_keys = X25519KeyPair::generate()?;
            let shared_secret = ephemeral_keys.diffie_hellman(pk)?;
            let ciphertext = Ciphertext::X25519(ephemeral_keys.public_key().clone());
            Ok((SharedSecret::new(shared_secret), ciphertext))
        },
        PublicKey::Hybrid(pk) => {
            let (secret, ciphertext) = pk.encapsulate()?;
            Ok((secret, Ciphertext::Hybrid(ciphertext)))
        },
        _ => Err(QuantumShieldError::InvalidKeyPairForKem),
    }
}

/// Decapsulate a shared secret using KEM
pub fn decapsulate_secret(
    ciphertext: &Ciphertext,
    private_key: &PrivateKey,
) -> Result<SharedSecret, QuantumShieldError> {
    match (ciphertext, private_key) {
        (Ciphertext::MlKem(ct), PrivateKey::MlKem(sk)) => {
            let secret = sk.decapsulate(ct)?;
            Ok(SharedSecret::new(secret))
        },
        (Ciphertext::X25519(pk), PrivateKey::X25519(sk)) => {
            let shared_secret = sk.diffie_hellman(pk)?;
            Ok(SharedSecret::new(shared_secret))
        },
        (Ciphertext::Hybrid(ct), PrivateKey::Hybrid(sk)) => {
            sk.decapsulate(ct)
        },
        _ => Err(QuantumShieldError::CiphertextPrivateKeyMismatch),
    }
}

/// Example usage
fn example_key_encapsulation() -> Result<(), QuantumShieldError> {
    // Generate KEM key pair
    let key_pair = generate_key_pair(Algorithm::MlKem, SecurityLevel::Level3)?;
    let public_key = key_pair.public_key();
    let private_key = key_pair.private_key();
    
    // Encapsulate shared secret
    let (shared_secret_alice, ciphertext) = encapsulate_secret(&public_key)?;
    
    // Decapsulate shared secret
    let shared_secret_bob = decapsulate_secret(&ciphertext, &private_key)?;
    
    // Verify shared secrets match
    assert_eq!(shared_secret_alice.as_bytes(), shared_secret_bob.as_bytes());
    println!("Key encapsulation successful");
    Ok(())
}
```

#### Symmetric Encryption

```rust
use quantum_shield::crypto::{SymmetricKey, Nonce, AuthenticatedEncryption};

/// Encrypt data using authenticated encryption
pub fn encrypt_data(
    plaintext: &[u8],
    key: &SymmetricKey,
    associated_data: &[u8],
) -> Result<(Vec<u8>, Nonce), QuantumShieldError> {
    let mut rng = ChaCha20Rng::from_entropy();
    let nonce = Nonce::generate(&mut rng);
    
    let aead = AuthenticatedEncryption::new(key)?;
    let ciphertext = aead.encrypt(&nonce, plaintext, associated_data)?;
    
    Ok((ciphertext, nonce))
}

/// Decrypt data using authenticated encryption
pub fn decrypt_data(
    ciphertext: &[u8],
    key: &SymmetricKey,
    nonce: &Nonce,
    associated_data: &[u8],
) -> Result<Vec<u8>, QuantumShieldError> {
    let aead = AuthenticatedEncryption::new(key)?;
    let plaintext = aead.decrypt(nonce, ciphertext, associated_data)?;
    Ok(plaintext)
}

/// Derive symmetric key from shared secret
pub fn derive_symmetric_key(
    shared_secret: &SharedSecret,
    salt: &[u8],
    info: &[u8],
) -> Result<SymmetricKey, QuantumShieldError> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
    let mut key_material = [0u8; 32];
    hkdf.expand(info, &mut key_material)?;
    
    Ok(SymmetricKey::new(key_material))
}

/// Example usage
fn example_symmetric_encryption() -> Result<(), QuantumShieldError> {
    let plaintext = b"Sensitive quantum-safe data";
    let associated_data = b"public metadata";
    
    // Derive symmetric key from KEM
    let kem_keys = generate_key_pair(Algorithm::MlKem, SecurityLevel::Level3)?;
    let (shared_secret, _) = encapsulate_secret(&kem_keys.public_key())?;
    
    let salt = b"quantum-shield-salt";
    let info = b"encryption-key-derivation";
    let symmetric_key = derive_symmetric_key(&shared_secret, salt, info)?;
    
    // Encrypt data
    let (ciphertext, nonce) = encrypt_data(plaintext, &symmetric_key, associated_data)?;
    
    // Decrypt data
    let decrypted = decrypt_data(&ciphertext, &symmetric_key, &nonce, associated_data)?;
    
    assert_eq!(plaintext, decrypted.as_slice());
    println!("Symmetric encryption successful");
    Ok(())
}
```

### Certificate Management API

#### Certificate Operations

```rust
use quantum_shield::{
    certificate::{Certificate, CertificateBuilder, CertificateRequest},
    trust_store::{TrustStore, TrustLevel},
};

/// Create a new certificate
pub fn create_certificate(
    subject: &str,
    issuer_key_pair: &KeyPair,
    subject_public_key: &PublicKey,
    validity_days: u32,
) -> Result<Certificate, QuantumShieldError> {
    let builder = CertificateBuilder::new()
        .subject(subject)?
        .issuer("CN=Quantum Shield CA")?
        .public_key(subject_public_key.clone())
        .validity_days(validity_days)
        .key_usage(&[KeyUsage::DigitalSignature, KeyUsage::KeyEncipherment])?
        .extended_key_usage(&[ExtendedKeyUsage::ClientAuth, ExtendedKeyUsage::ServerAuth])?;
    
    let certificate = builder.sign(issuer_key_pair)?;
    Ok(certificate)
}

/// Create a certificate signing request (CSR)
pub fn create_certificate_request(
    subject: &str,
    key_pair: &KeyPair,
    attributes: &[CsrAttribute],
) -> Result<CertificateRequest, QuantumShieldError> {
    let builder = CertificateRequestBuilder::new()
        .subject(subject)?
        .public_key(key_pair.public_key())
        .attributes(attributes);
    
    let csr = builder.sign(key_pair)?;
    Ok(csr)
}

/// Verify certificate chain
pub async fn verify_certificate_chain(
    certificate: &Certificate,
    trust_store: &TrustStore,
) -> Result<CertificateVerificationResult, QuantumShieldError> {
    let verification_result = trust_store.verify_certificate(certificate).await?;
    Ok(verification_result)
}

/// Example usage
async fn example_certificate_operations() -> Result<(), QuantumShieldError> {
    // Create CA key pair
    let ca_keys = generate_key_pair(Algorithm::MlDsa, SecurityLevel::Level3)?;
    
    // Create end-entity key pair
    let ee_keys = generate_key_pair(Algorithm::MlDsa, SecurityLevel::Level3)?;
    
    // Create certificate
    let certificate = create_certificate(
        "CN=example.com,O=Example Corp",
        &ca_keys,
        &ee_keys.public_key(),
        365, // Valid for 1 year
    )?;
    
    // Initialize trust store
    let mut trust_store = TrustStore::new(TrustStoreConfig::default()).await?;
    
    // Import CA certificate as trust anchor
    let ca_cert = create_self_signed_certificate(&ca_keys, "CN=Quantum Shield CA")?;
    trust_store.add_trust_anchor(&ca_cert, TrustLevel::RootAuthority).await?;
    
    // Verify certificate
    let verification_result = verify_certificate_chain(&certificate, &trust_store).await?;
    
    println!("Certificate verification result: {:?}", verification_result);
    Ok(())
}
```

#### Trust Store Management

```rust
/// Initialize trust store with default configuration
pub async fn initialize_trust_store(
    database_path: &str,
) -> Result<TrustStore, QuantumShieldError> {
    let config = TrustStoreConfig {
        storage_config: StorageConfig {
            backend: StorageBackend::Sqlite,
            connection_string: database_path.to_string(),
            encryption_key: None,
        },
        validation_config: ValidationConfig::default(),
        revocation_config: RevocationConfig::default(),
        trust_policy_config: TrustPolicyConfig::default(),
        cache_config: CacheConfig::default(),
        security_config: SecurityConfig::default(),
    };
    
    TrustStore::new(config).await
}

/// Add certificate to trust store
pub async fn add_certificate_to_trust_store(
    trust_store: &mut TrustStore,
    certificate: Certificate,
    trust_level: TrustLevel,
) -> Result<CertificateId, QuantumShieldError> {
    let cert_id = trust_store.import_certificate(certificate, Some(trust_level)).await?;
    Ok(cert_id)
}

/// Search certificates in trust store
pub async fn search_certificates(
    trust_store: &TrustStore,
    criteria: CertificateSearchCriteria,
) -> Result<Vec<Certificate>, QuantumShieldError> {
    let certificates = trust_store.find_certificates(&criteria).await?;
    Ok(certificates)
}

/// Update certificate trust level
pub async fn update_certificate_trust_level(
    trust_store: &mut TrustStore,
    certificate_id: &CertificateId,
    new_trust_level: TrustLevel,
) -> Result<(), QuantumShieldError> {
    trust_store.update_certificate_trust(
        certificate_id,
        new_trust_level,
        TrustUpdateReason::ManualUpdate,
    ).await?;
    Ok(())
}

/// Example usage
async fn example_trust_store_operations() -> Result<(), QuantumShieldError> {
    // Initialize trust store
    let mut trust_store = initialize_trust_store("quantum_shield.db").await?;
    
    // Create and add certificate
    let key_pair = generate_key_pair(Algorithm::MlDsa, SecurityLevel::Level3)?;
    let certificate = create_self_signed_certificate(&key_pair, "CN=Test Certificate")?;
    
    let cert_id = add_certificate_to_trust_store(
        &mut trust_store,
        certificate,
        TrustLevel::Trusted,
    ).await?;
    
    // Search for certificates
    let search_criteria = CertificateSearchCriteria::ByTrustLevel(TrustLevel::Trusted);
    let found_certificates = search_certificates(&trust_store, search_criteria).await?;
    
    println!("Found {} trusted certificates", found_certificates.len());
    
    // Update trust level
    update_certificate_trust_level(
        &mut trust_store,
        &cert_id,
        TrustLevel::HighlyTrusted,
    ).await?;
    
    Ok(())
}
```

## REST API

### Authentication

All REST API endpoints require authentication using API keys or JWT tokens.

```http
Authorization: Bearer <jwt_token>
# or
X-API-Key: <api_key>
```

### Endpoints

#### Key Management

**Generate Key Pair**

```http
POST /api/v1/keys/generate
Content-Type: application/json

{
    "algorithm": "ml-dsa",
    "security_level": "level3",
    "key_id": "optional-key-identifier"
}
```

Response:
```json
{
    "key_id": "key_12345",
    "algorithm": "ml-dsa",
    "security_level": "level3",
    "public_key": {
        "format": "der",
        "data": "base64-encoded-public-key"
    },
    "created_at": "2024-01-15T10:30:00Z"
}
```

**Get Public Key**

```http
GET /api/v1/keys/{key_id}/public
```

Response:
```json
{
    "key_id": "key_12345",
    "algorithm": "ml-dsa",
    "security_level": "level3",
    "public_key": {
        "format": "der",
        "data": "base64-encoded-public-key"
    },
    "created_at": "2024-01-15T10:30:00Z"
}
```

**List Keys**

```http
GET /api/v1/keys?algorithm=ml-dsa&security_level=level3
```

Response:
```json
{
    "keys": [
        {
            "key_id": "key_12345",
            "algorithm": "ml-dsa",
            "security_level": "level3",
            "created_at": "2024-01-15T10:30:00Z"
        }
    ],
    "total": 1,
    "page": 1,
    "per_page": 50
}
```

**Delete Key**

```http
DELETE /api/v1/keys/{key_id}
```

Response:
```json
{
    "message": "Key deleted successfully",
    "key_id": "key_12345"
}
```

#### Digital Signatures

**Sign Data**

```http
POST /api/v1/signatures/sign
Content-Type: application/json

{
    "key_id": "key_12345",
    "data": "base64-encoded-data-to-sign",
    "algorithm": "ml-dsa-65"
}
```

Response:
```json
{
    "signature": {
        "algorithm": "ml-dsa-65",
        "format": "der",
        "data": "base64-encoded-signature"
    },
    "key_id": "key_12345",
    "signed_at": "2024-01-15T10:35:00Z"
}
```

**Verify Signature**

```http
POST /api/v1/signatures/verify
Content-Type: application/json

{
    "data": "base64-encoded-original-data",
    "signature": {
        "algorithm": "ml-dsa-65",
        "format": "der",
        "data": "base64-encoded-signature"
    },
    "public_key": {
        "format": "der",
        "data": "base64-encoded-public-key"
    }
}
```

Response:
```json
{
    "valid": true,
    "algorithm": "ml-dsa-65",
    "verified_at": "2024-01-15T10:40:00Z"
}
```

#### Key Encapsulation

**Encapsulate Secret**

```http
POST /api/v1/kem/encapsulate
Content-Type: application/json

{
    "public_key": {
        "format": "der",
        "data": "base64-encoded-public-key"
    },
    "algorithm": "ml-kem-768"
}
```

Response:
```json
{
    "shared_secret": "base64-encoded-shared-secret",
    "ciphertext": "base64-encoded-ciphertext",
    "algorithm": "ml-kem-768",
    "encapsulated_at": "2024-01-15T10:45:00Z"
}
```

**Decapsulate Secret**

```http
POST /api/v1/kem/decapsulate
Content-Type: application/json

{
    "key_id": "key_67890",
    "ciphertext": "base64-encoded-ciphertext",
    "algorithm": "ml-kem-768"
}
```

Response:
```json
{
    "shared_secret": "base64-encoded-shared-secret",
    "algorithm": "ml-kem-768",
    "decapsulated_at": "2024-01-15T10:50:00Z"
}
```

#### Certificate Management

**Create Certificate**

```http
POST /api/v1/certificates
Content-Type: application/json

{
    "subject": "CN=example.com,O=Example Corp",
    "issuer_key_id": "ca_key_123",
    "subject_public_key": {
        "format": "der",
        "data": "base64-encoded-public-key"
    },
    "validity_days": 365,
    "key_usage": ["digital_signature", "key_encipherment"],
    "extended_key_usage": ["server_auth", "client_auth"]
}
```

Response:
```json
{
    "certificate_id": "cert_456",
    "certificate": {
        "format": "der",
        "data": "base64-encoded-certificate"
    },
    "subject": "CN=example.com,O=Example Corp",
    "issuer": "CN=Quantum Shield CA",
    "serial_number": "123456789",
    "not_before": "2024-01-15T00:00:00Z",
    "not_after": "2025-01-15T00:00:00Z",
    "created_at": "2024-01-15T11:00:00Z"
}
```

**Get Certificate**

```http
GET /api/v1/certificates/{certificate_id}
```

Response:
```json
{
    "certificate_id": "cert_456",
    "certificate": {
        "format": "der",
        "data": "base64-encoded-certificate"
    },
    "subject": "CN=example.com,O=Example Corp",
    "issuer": "CN=Quantum Shield CA",
    "serial_number": "123456789",
    "not_before": "2024-01-15T00:00:00Z",
    "not_after": "2025-01-15T00:00:00Z",
    "trust_level": "trusted",
    "created_at": "2024-01-15T11:00:00Z"
}
```

**Verify Certificate**

```http
POST /api/v1/certificates/verify
Content-Type: application/json

{
    "certificate": {
        "format": "der",
        "data": "base64-encoded-certificate"
    }
}
```

Response:
```json
{
    "valid": true,
    "trust_level": "trusted",
    "validation_result": {
        "structure_valid": true,
        "signature_valid": true,
        "time_valid": true,
        "revocation_status": "valid",
        "trust_path": ["cert_456", "ca_cert_123"]
    },
    "verified_at": "2024-01-15T11:10:00Z"
}
```

**Search Certificates**

```http
GET /api/v1/certificates/search?subject=example.com&trust_level=trusted
```

Response:
```json
{
    "certificates": [
        {
            "certificate_id": "cert_456",
            "subject": "CN=example.com,O=Example Corp",
            "issuer": "CN=Quantum Shield CA",
            "trust_level": "trusted",
            "not_after": "2025-01-15T00:00:00Z"
        }
    ],
    "total": 1,
    "page": 1,
    "per_page": 50
}
```

#### Trust Store Management

**Add Trust Anchor**

```http
POST /api/v1/trust-store/anchors
Content-Type: application/json

{
    "name": "Quantum Shield Root CA",
    "certificate": {
        "format": "der",
        "data": "base64-encoded-certificate"
    },
    "trust_level": "root_authority"
}
```

Response:
```json
{
    "anchor_id": "anchor_789",
    "name": "Quantum Shield Root CA",
    "trust_level": "root_authority",
    "created_at": "2024-01-15T11:20:00Z"
}
```

**List Trust Anchors**

```http
GET /api/v1/trust-store/anchors
```

Response:
```json
{
    "anchors": [
        {
            "anchor_id": "anchor_789",
            "name": "Quantum Shield Root CA",
            "trust_level": "root_authority",
            "created_at": "2024-01-15T11:20:00Z"
        }
    ],
    "total": 1
}
```

**Update Certificate Trust Level**

```http
PUT /api/v1/trust-store/certificates/{certificate_id}/trust
Content-Type: application/json

{
    "trust_level": "highly_trusted",
    "reason": "manual_update"
}
```

Response:
```json
{
    "certificate_id": "cert_456",
    "old_trust_level": "trusted",
    "new_trust_level": "highly_trusted",
    "updated_at": "2024-01-15T11:30:00Z"
}
```

### Error Responses

All API endpoints return consistent error responses:

```json
{
    "error": {
        "code": "INVALID_ALGORITHM",
        "message": "The specified algorithm is not supported",
        "details": {
            "algorithm": "unsupported-algorithm",
            "supported_algorithms": ["ml-dsa", "ml-kem", "falcon", "sphincs-plus"]
        }
    },
    "timestamp": "2024-01-15T12:00:00Z",
    "request_id": "req_123456"
}
```

Common error codes:
- `INVALID_ALGORITHM`: Unsupported cryptographic algorithm
- `INVALID_SECURITY_LEVEL`: Unsupported security level
- `KEY_NOT_FOUND`: Specified key does not exist
- `CERTIFICATE_NOT_FOUND`: Specified certificate does not exist
- `INVALID_SIGNATURE`: Signature verification failed
- `INVALID_CERTIFICATE`: Certificate validation failed
- `UNAUTHORIZED`: Authentication required or failed
- `FORBIDDEN`: Insufficient permissions
- `RATE_LIMITED`: Too many requests

## SDK Integration

### Python SDK

```python
import quantum_shield

# Initialize client
client = quantum_shield.Client(
    api_key="your-api-key",
    base_url="https://api.quantum-shield.com"
)

# Generate key pair
key_pair = client.keys.generate(
    algorithm="ml-dsa",
    security_level="level3"
)

# Sign data
signature = client.signatures.sign(
    key_id=key_pair.key_id,
    data=b"Hello, Quantum World!",
    algorithm="ml-dsa-65"
)

# Verify signature
is_valid = client.signatures.verify(
    data=b"Hello, Quantum World!",
    signature=signature,
    public_key=key_pair.public_key
)

print(f"Signature valid: {is_valid}")
```

### JavaScript SDK

```javascript
import { QuantumShieldClient } from '@quantum-shield/sdk';

// Initialize client
const client = new QuantumShieldClient({
    apiKey: 'your-api-key',
    baseUrl: 'https://api.quantum-shield.com'
});

// Generate key pair
const keyPair = await client.keys.generate({
    algorithm: 'ml-dsa',
    securityLevel: 'level3'
});

// Sign data
const signature = await client.signatures.sign({
    keyId: keyPair.keyId,
    data: new TextEncoder().encode('Hello, Quantum World!'),
    algorithm: 'ml-dsa-65'
});

// Verify signature
const isValid = await client.signatures.verify({
    data: new TextEncoder().encode('Hello, Quantum World!'),
    signature: signature,
    publicKey: keyPair.publicKey
});

console.log(`Signature valid: ${isValid}`);
```

### Go SDK

```go
package main

import (
    "fmt"
    "github.com/quantum-shield/go-sdk"
)

func main() {
    // Initialize client
    client := quantumshield.NewClient(&quantumshield.Config{
        APIKey:  "your-api-key",
        BaseURL: "https://api.quantum-shield.com",
    })

    // Generate key pair
    keyPair, err := client.Keys.Generate(&quantumshield.KeyGenerationRequest{
        Algorithm:     "ml-dsa",
        SecurityLevel: "level3",
    })
    if err != nil {
        panic(err)
    }

    // Sign data
    signature, err := client.Signatures.Sign(&quantumshield.SignRequest{
        KeyID:     keyPair.KeyID,
        Data:      []byte("Hello, Quantum World!"),
        Algorithm: "ml-dsa-65",
    })
    if err != nil {
        panic(err)
    }

    // Verify signature
    isValid, err := client.Signatures.Verify(&quantumshield.VerifyRequest{
        Data:      []byte("Hello, Quantum World!"),
        Signature: signature,
        PublicKey: keyPair.PublicKey,
    })
    if err != nil {
        panic(err)
    }

    fmt.Printf("Signature valid: %t\n", isValid)
}
```

### Java SDK

```java
import com.quantumshield.sdk.QuantumShieldClient;
import com.quantumshield.sdk.models.*;

public class QuantumShieldExample {
    public static void main(String[] args) {
        // Initialize client
        QuantumShieldClient client = QuantumShieldClient.builder()
            .apiKey("your-api-key")
            .baseUrl("https://api.quantum-shield.com")
            .build();

        try {
            // Generate key pair
            KeyPair keyPair = client.keys().generate(
                KeyGenerationRequest.builder()
                    .algorithm("ml-dsa")
                    .securityLevel("level3")
                    .build()
            );

            // Sign data
            Signature signature = client.signatures().sign(
                SignRequest.builder()
                    .keyId(keyPair.getKeyId())
                    .data("Hello, Quantum World!".getBytes())
                    .algorithm("ml-dsa-65")
                    .build()
            );

            // Verify signature
            boolean isValid = client.signatures().verify(
                VerifyRequest.builder()
                    .data("Hello, Quantum World!".getBytes())
                    .signature(signature)
                    .publicKey(keyPair.getPublicKey())
                    .build()
            );

            System.out.println("Signature valid: " + isValid);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## Configuration

### Environment Variables

```bash
# API Configuration
QUANTUM_SHIELD_API_KEY=your-api-key
QUANTUM_SHIELD_BASE_URL=https://api.quantum-shield.com
QUANTUM_SHIELD_TIMEOUT=30s

# Database Configuration
QUANTUM_SHIELD_DB_URL=postgresql://user:pass@localhost/quantum_shield
QUANTUM_SHIELD_DB_ENCRYPTION_KEY=base64-encoded-key

# Security Configuration
QUANTUM_SHIELD_LOG_LEVEL=info
QUANTUM_SHIELD_AUDIT_ENABLED=true
QUANTUM_SHIELD_RATE_LIMIT=1000

# Algorithm Configuration
QUANTUM_SHIELD_DEFAULT_ALGORITHM=ml-dsa
QUANTUM_SHIELD_DEFAULT_SECURITY_LEVEL=level3
QUANTUM_SHIELD_ENABLE_CLASSICAL_ALGORITHMS=false
```

### Configuration File

```yaml
# quantum-shield.yaml
api:
  key: "your-api-key"
  base_url: "https://api.quantum-shield.com"
  timeout: "30s"
  retry_attempts: 3

database:
  url: "postgresql://user:pass@localhost/quantum_shield"
  encryption_key: "base64-encoded-key"
  max_connections: 100

security:
  log_level: "info"
  audit_enabled: true
  rate_limit: 1000
  allowed_origins: ["https://example.com"]

algorithms:
  default_algorithm: "ml-dsa"
  default_security_level: "level3"
  enable_classical: false
  supported_algorithms:
    - "ml-dsa"
    - "ml-kem"
    - "falcon"
    - "sphincs-plus"

trust_store:
  validation:
    check_revocation: true
    require_quantum_safe: true
    max_chain_length: 10
  
  policies:
    - name: "Quantum Safe Only"
      conditions:
        - type: "quantum_safe_required"
      actions:
        - type: "allow"
          trust_level: "trusted"
```

This comprehensive API documentation provides complete coverage of Quantum Shield's cryptographic operations, certificate management, and trust store functionality with practical examples and integration guides.

