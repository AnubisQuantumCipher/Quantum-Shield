# Quantum Shield File Format Specification

## Overview

The Quantum Shield File Format (QSFF) is a comprehensive binary format designed to store quantum-safe cryptographic data, certificates, keys, and signatures. This document provides the complete specification for QSFF, including structure definitions, encoding rules, and implementation guidelines.

## Format Versioning

### Version History

| Version | Release Date | Major Changes |
|---------|--------------|---------------|
| 1.0 | 2024-01-01 | Initial release with basic quantum-safe support |
| 2.0 | 2024-06-01 | Added hybrid cryptography and enhanced metadata |
| 2.1 | 2024-09-01 | Added trust store integration and policy support |
| 3.0 | 2024-12-01 | Full post-quantum standardization compliance |

### Version Compatibility

```rust
/// QSFF version information
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QsffVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl QsffVersion {
    pub const V1_0: QsffVersion = QsffVersion { major: 1, minor: 0, patch: 0 };
    pub const V2_0: QsffVersion = QsffVersion { major: 2, minor: 0, patch: 0 };
    pub const V2_1: QsffVersion = QsffVersion { major: 2, minor: 1, patch: 0 };
    pub const V3_0: QsffVersion = QsffVersion { major: 3, minor: 0, patch: 0 };
    pub const CURRENT: QsffVersion = Self::V3_0;
    
    /// Check if this version is compatible with another version
    pub fn is_compatible_with(&self, other: &QsffVersion) -> bool {
        // Major version must match for compatibility
        self.major == other.major
    }
    
    /// Check if this version supports a specific feature
    pub fn supports_feature(&self, feature: QsffFeature) -> bool {
        match feature {
            QsffFeature::HybridCryptography => self.major >= 2,
            QsffFeature::TrustStoreIntegration => self >= &Self::V2_1,
            QsffFeature::PostQuantumStandardization => self.major >= 3,
            QsffFeature::BasicQuantumSafe => true, // Supported in all versions
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum QsffFeature {
    BasicQuantumSafe,
    HybridCryptography,
    TrustStoreIntegration,
    PostQuantumStandardization,
}
```

## File Structure

### Overall Layout

```
QSFF File Structure:
┌─────────────────────────────────────────────────────────────┐
│ File Header (32 bytes)                                      │
├─────────────────────────────────────────────────────────────┤
│ Metadata Section (variable length)                         │
├─────────────────────────────────────────────────────────────┤
│ Algorithm Manifest (variable length)                       │
├─────────────────────────────────────────────────────────────┤
│ Content Sections (variable length)                         │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Section Header (16 bytes)                               │ │
│ ├─────────────────────────────────────────────────────────┤ │
│ │ Section Data (variable length)                          │ │
│ └─────────────────────────────────────────────────────────┘ │
│ ... (additional sections)                                   │
├─────────────────────────────────────────────────────────────┤
│ Signature Block (variable length)                          │
├─────────────────────────────────────────────────────────────┤
│ File Footer (32 bytes)                                     │
└─────────────────────────────────────────────────────────────┘
```

### File Header

```rust
/// QSFF file header structure (32 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct QsffFileHeader {
    /// Magic number: "QSFF" (0x51534646)
    pub magic: [u8; 4],
    
    /// Format version
    pub version: QsffVersion,
    
    /// Reserved byte for alignment
    pub reserved: u8,
    
    /// File flags
    pub flags: QsffFlags,
    
    /// Total file size in bytes
    pub file_size: u64,
    
    /// Number of content sections
    pub section_count: u32,
    
    /// Offset to metadata section
    pub metadata_offset: u32,
    
    /// Offset to algorithm manifest
    pub manifest_offset: u32,
    
    /// Offset to first content section
    pub content_offset: u32,
    
    /// Offset to signature block
    pub signature_offset: u32,
}

/// File flags bitfield
#[derive(Debug, Clone, Copy)]
pub struct QsffFlags(pub u32);

impl QsffFlags {
    pub const ENCRYPTED: u32 = 0x0001;
    pub const SIGNED: u32 = 0x0002;
    pub const COMPRESSED: u32 = 0x0004;
    pub const HYBRID_CRYPTO: u32 = 0x0008;
    pub const QUANTUM_SAFE: u32 = 0x0010;
    pub const TRUST_ANCHORED: u32 = 0x0020;
    pub const FORWARD_SECURE: u32 = 0x0040;
    pub const MULTI_RECIPIENT: u32 = 0x0080;
    
    pub fn new() -> Self {
        QsffFlags(0)
    }
    
    pub fn set_flag(&mut self, flag: u32) {
        self.0 |= flag;
    }
    
    pub fn has_flag(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

impl QsffFileHeader {
    pub fn new(version: QsffVersion) -> Self {
        QsffFileHeader {
            magic: *b"QSFF",
            version,
            reserved: 0,
            flags: QsffFlags::new(),
            file_size: 0,
            section_count: 0,
            metadata_offset: 0,
            manifest_offset: 0,
            content_offset: 0,
            signature_offset: 0,
        }
    }
    
    pub fn validate(&self) -> Result<(), QsffError> {
        if self.magic != *b"QSFF" {
            return Err(QsffError::InvalidMagicNumber);
        }
        
        if !self.version.is_compatible_with(&QsffVersion::CURRENT) {
            return Err(QsffError::UnsupportedVersion(self.version));
        }
        
        // Validate offset ordering
        if self.metadata_offset < std::mem::size_of::<QsffFileHeader>() as u32 {
            return Err(QsffError::InvalidOffset("metadata_offset"));
        }
        
        if self.manifest_offset <= self.metadata_offset {
            return Err(QsffError::InvalidOffset("manifest_offset"));
        }
        
        if self.content_offset <= self.manifest_offset {
            return Err(QsffError::InvalidOffset("content_offset"));
        }
        
        Ok(())
    }
}
```

### Metadata Section

```rust
/// File metadata structure
#[derive(Debug, Clone)]
pub struct QsffMetadata {
    /// Metadata header
    pub header: MetadataHeader,
    
    /// Creator information
    pub creator: CreatorInfo,
    
    /// Timestamp information
    pub timestamps: TimestampInfo,
    
    /// Content description
    pub content_info: ContentInfo,
    
    /// Security parameters
    pub security_params: SecurityParameters,
    
    /// Custom attributes
    pub custom_attributes: Vec<CustomAttribute>,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MetadataHeader {
    /// Metadata section size
    pub section_size: u32,
    
    /// Metadata version
    pub metadata_version: u16,
    
    /// Number of custom attributes
    pub attribute_count: u16,
    
    /// Checksum of metadata content
    pub checksum: u32,
}

#[derive(Debug, Clone)]
pub struct CreatorInfo {
    /// Application name that created the file
    pub application: String,
    
    /// Application version
    pub version: String,
    
    /// Creator organization
    pub organization: Option<String>,
    
    /// Creator contact information
    pub contact: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TimestampInfo {
    /// File creation time (Unix timestamp)
    pub created_at: u64,
    
    /// Last modification time (Unix timestamp)
    pub modified_at: u64,
    
    /// Content validity start time (Unix timestamp)
    pub valid_from: Option<u64>,
    
    /// Content validity end time (Unix timestamp)
    pub valid_until: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ContentInfo {
    /// Content type identifier
    pub content_type: ContentType,
    
    /// Content description
    pub description: Option<String>,
    
    /// Content classification level
    pub classification: SecurityClassification,
    
    /// Content handling instructions
    pub handling_instructions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    /// Raw binary data
    RawData = 0x01,
    
    /// X.509 certificate
    Certificate = 0x02,
    
    /// Private key material
    PrivateKey = 0x03,
    
    /// Public key material
    PublicKey = 0x04,
    
    /// Digital signature
    Signature = 0x05,
    
    /// Encrypted message
    EncryptedMessage = 0x06,
    
    /// Key encapsulation data
    KeyEncapsulation = 0x07,
    
    /// Trust store export
    TrustStore = 0x08,
    
    /// Certificate revocation list
    RevocationList = 0x09,
    
    /// Quantum-safe container
    QuantumContainer = 0x0A,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityClassification {
    Unclassified = 0,
    Restricted = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
}

#[derive(Debug, Clone)]
pub struct SecurityParameters {
    /// Required security level
    pub security_level: SecurityLevel,
    
    /// Quantum safety requirement
    pub quantum_safe_required: bool,
    
    /// Forward secrecy requirement
    pub forward_secrecy_required: bool,
    
    /// Minimum key sizes
    pub min_symmetric_key_size: u32,
    pub min_asymmetric_key_size: u32,
    
    /// Allowed algorithms
    pub allowed_algorithms: Vec<AlgorithmIdentifier>,
    
    /// Prohibited algorithms
    pub prohibited_algorithms: Vec<AlgorithmIdentifier>,
}

#[derive(Debug, Clone)]
pub struct CustomAttribute {
    /// Attribute name
    pub name: String,
    
    /// Attribute value
    pub value: AttributeValue,
    
    /// Attribute criticality
    pub critical: bool,
}

#[derive(Debug, Clone)]
pub enum AttributeValue {
    String(String),
    Integer(i64),
    Boolean(bool),
    Binary(Vec<u8>),
    Timestamp(u64),
}
```

### Algorithm Manifest

```rust
/// Public Algorithm Manifest (PAM) structure
#[derive(Debug, Clone)]
pub struct AlgorithmManifest {
    /// Manifest header
    pub header: ManifestHeader,
    
    /// List of algorithms used in the file
    pub algorithms: Vec<AlgorithmEntry>,
    
    /// Algorithm compatibility matrix
    pub compatibility_matrix: CompatibilityMatrix,
    
    /// Security assertions
    pub security_assertions: Vec<SecurityAssertion>,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ManifestHeader {
    /// Manifest section size
    pub section_size: u32,
    
    /// Manifest version
    pub manifest_version: u16,
    
    /// Number of algorithm entries
    pub algorithm_count: u16,
    
    /// Number of security assertions
    pub assertion_count: u16,
    
    /// Manifest flags
    pub flags: u16,
    
    /// Checksum of manifest content
    pub checksum: u32,
}

#[derive(Debug, Clone)]
pub struct AlgorithmEntry {
    /// Algorithm identifier
    pub algorithm_id: AlgorithmIdentifier,
    
    /// Algorithm name (human-readable)
    pub name: String,
    
    /// Algorithm category
    pub category: AlgorithmCategory,
    
    /// Security level provided
    pub security_level: SecurityLevel,
    
    /// Quantum safety status
    pub quantum_safe: bool,
    
    /// Algorithm parameters
    pub parameters: AlgorithmParameters,
    
    /// Implementation details
    pub implementation: ImplementationInfo,
    
    /// Usage context within the file
    pub usage_context: Vec<UsageContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmCategory {
    SymmetricEncryption,
    AsymmetricEncryption,
    DigitalSignature,
    KeyExchange,
    KeyDerivation,
    HashFunction,
    MessageAuthentication,
    KeyEncapsulation,
    Hybrid,
}

#[derive(Debug, Clone)]
pub struct AlgorithmParameters {
    /// Key size in bits
    pub key_size: Option<u32>,
    
    /// Block size in bits (for block ciphers)
    pub block_size: Option<u32>,
    
    /// Hash output size in bits
    pub hash_size: Option<u32>,
    
    /// Signature size in bytes
    pub signature_size: Option<u32>,
    
    /// Ciphertext expansion factor
    pub ciphertext_expansion: Option<f64>,
    
    /// Algorithm-specific parameters
    pub specific_params: HashMap<String, ParameterValue>,
}

#[derive(Debug, Clone)]
pub enum ParameterValue {
    Integer(i64),
    Float(f64),
    String(String),
    Binary(Vec<u8>),
    Boolean(bool),
}

#[derive(Debug, Clone)]
pub struct ImplementationInfo {
    /// Implementation name/library
    pub implementation_name: String,
    
    /// Implementation version
    pub version: String,
    
    /// Certification status
    pub certification: CertificationStatus,
    
    /// Performance characteristics
    pub performance: PerformanceMetrics,
    
    /// Security features
    pub security_features: Vec<SecurityFeature>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificationStatus {
    None,
    SelfCertified,
    ThirdPartyTested,
    FipsValidated,
    CommonCriteriaEvaluated,
    NistApproved,
}

#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    /// Key generation time (microseconds)
    pub keygen_time_us: Option<u64>,
    
    /// Signing time (microseconds)
    pub sign_time_us: Option<u64>,
    
    /// Verification time (microseconds)
    pub verify_time_us: Option<u64>,
    
    /// Encryption time per KB (microseconds)
    pub encrypt_time_per_kb_us: Option<u64>,
    
    /// Decryption time per KB (microseconds)
    pub decrypt_time_per_kb_us: Option<u64>,
    
    /// Memory usage (bytes)
    pub memory_usage_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFeature {
    ConstantTime,
    SideChannelResistant,
    FaultTolerant,
    ForwardSecure,
    PostQuantumSecure,
    HybridSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UsageContext {
    KeyGeneration,
    Encryption,
    Decryption,
    Signing,
    Verification,
    KeyExchange,
    KeyDerivation,
    Authentication,
    Integrity,
}

#[derive(Debug, Clone)]
pub struct CompatibilityMatrix {
    /// Algorithm compatibility relationships
    pub relationships: Vec<CompatibilityRelationship>,
}

#[derive(Debug, Clone)]
pub struct CompatibilityRelationship {
    /// Primary algorithm
    pub algorithm_a: AlgorithmIdentifier,
    
    /// Secondary algorithm
    pub algorithm_b: AlgorithmIdentifier,
    
    /// Compatibility type
    pub relationship_type: CompatibilityType,
    
    /// Compatibility level
    pub compatibility_level: CompatibilityLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityType {
    /// Algorithms can be used together
    Compatible,
    
    /// Algorithms complement each other
    Complementary,
    
    /// Algorithms are mutually exclusive
    Exclusive,
    
    /// One algorithm depends on the other
    Dependent,
    
    /// Algorithms provide equivalent functionality
    Equivalent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompatibilityLevel {
    Full,
    Partial,
    Limited,
    None,
}

#[derive(Debug, Clone)]
pub struct SecurityAssertion {
    /// Assertion type
    pub assertion_type: AssertionType,
    
    /// Assertion statement
    pub statement: String,
    
    /// Evidence supporting the assertion
    pub evidence: Vec<Evidence>,
    
    /// Assertion confidence level
    pub confidence: ConfidenceLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssertionType {
    QuantumSafety,
    SecurityLevel,
    PerformanceGuarantee,
    CompatibilityGuarantee,
    ComplianceStatement,
    ThreatResistance,
}

#[derive(Debug, Clone)]
pub struct Evidence {
    /// Evidence type
    pub evidence_type: EvidenceType,
    
    /// Evidence description
    pub description: String,
    
    /// Reference to supporting documentation
    pub reference: Option<String>,
    
    /// Evidence data
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceType {
    MathematicalProof,
    SecurityAnalysis,
    PerformanceBenchmark,
    CertificationReport,
    PeerReview,
    StandardsCompliance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
    Verified,
}
```

## Content Sections

### Section Structure

```rust
/// Content section header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SectionHeader {
    /// Section type identifier
    pub section_type: SectionType,
    
    /// Section flags
    pub flags: u32,
    
    /// Section data size (excluding header)
    pub data_size: u32,
    
    /// Section data checksum
    pub checksum: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SectionType {
    /// Raw binary data
    RawData = 0x01000000,
    
    /// X.509 certificate data
    Certificate = 0x02000000,
    
    /// Private key data
    PrivateKey = 0x03000000,
    
    /// Public key data
    PublicKey = 0x04000000,
    
    /// Digital signature data
    Signature = 0x05000000,
    
    /// Encrypted content
    EncryptedContent = 0x06000000,
    
    /// Key encapsulation data
    KeyEncapsulation = 0x07000000,
    
    /// Trust store data
    TrustStore = 0x08000000,
    
    /// Revocation data
    RevocationData = 0x09000000,
    
    /// Metadata extension
    MetadataExtension = 0x0A000000,
    
    /// Custom section
    Custom = 0xFF000000,
}

impl SectionHeader {
    pub fn new(section_type: SectionType, data_size: u32) -> Self {
        SectionHeader {
            section_type,
            flags: 0,
            data_size,
            checksum: 0,
        }
    }
    
    pub fn calculate_checksum(&mut self, data: &[u8]) {
        use crc32fast::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(data);
        self.checksum = hasher.finalize();
    }
    
    pub fn verify_checksum(&self, data: &[u8]) -> bool {
        use crc32fast::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(data);
        hasher.finalize() == self.checksum
    }
}
```

### Certificate Section

```rust
/// Certificate section data structure
#[derive(Debug, Clone)]
pub struct CertificateSection {
    /// Certificate format
    pub format: CertificateFormat,
    
    /// Certificate data
    pub certificate_data: Vec<u8>,
    
    /// Certificate chain (if applicable)
    pub certificate_chain: Option<Vec<Vec<u8>>>,
    
    /// Trust information
    pub trust_info: Option<TrustInformation>,
    
    /// Validation metadata
    pub validation_metadata: Option<ValidationMetadata>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateFormat {
    /// DER-encoded X.509 certificate
    X509Der,
    
    /// PEM-encoded X.509 certificate
    X509Pem,
    
    /// Quantum-safe certificate format
    QuantumSafeCert,
    
    /// OpenPGP certificate
    OpenPgp,
    
    /// Custom certificate format
    Custom(u32),
}

#[derive(Debug, Clone)]
pub struct TrustInformation {
    /// Trust level
    pub trust_level: TrustLevel,
    
    /// Trust anchor reference
    pub trust_anchor_id: Option<String>,
    
    /// Trust establishment date
    pub established_at: u64,
    
    /// Trust expiration date
    pub expires_at: Option<u64>,
    
    /// Trust constraints
    pub constraints: Vec<TrustConstraint>,
}

#[derive(Debug, Clone)]
pub struct ValidationMetadata {
    /// Last validation timestamp
    pub last_validated: u64,
    
    /// Validation result
    pub validation_result: ValidationResult,
    
    /// Revocation status
    pub revocation_status: RevocationStatus,
    
    /// Validation errors/warnings
    pub validation_issues: Vec<ValidationIssue>,
}
```

### Key Section

```rust
/// Key section data structure
#[derive(Debug, Clone)]
pub struct KeySection {
    /// Key type
    pub key_type: KeyType,
    
    /// Key format
    pub format: KeyFormat,
    
    /// Key usage constraints
    pub usage: Vec<KeyUsage>,
    
    /// Key material (encrypted if private)
    pub key_data: Vec<u8>,
    
    /// Key derivation information
    pub derivation_info: Option<KeyDerivationInfo>,
    
    /// Key protection information
    pub protection_info: Option<KeyProtectionInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// Symmetric key
    Symmetric,
    
    /// Asymmetric public key
    AsymmetricPublic,
    
    /// Asymmetric private key
    AsymmetricPrivate,
    
    /// Key pair (public + private)
    KeyPair,
    
    /// Derived key
    Derived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// Raw key bytes
    Raw,
    
    /// PKCS#8 format
    Pkcs8,
    
    /// PKCS#1 format
    Pkcs1,
    
    /// SEC1 format
    Sec1,
    
    /// OpenSSH format
    OpenSsh,
    
    /// JWK format
    Jwk,
    
    /// Quantum-safe key format
    QuantumSafe,
}

#[derive(Debug, Clone)]
pub struct KeyDerivationInfo {
    /// Derivation algorithm
    pub algorithm: KeyDerivationAlgorithm,
    
    /// Derivation parameters
    pub parameters: KeyDerivationParameters,
    
    /// Source key reference
    pub source_key_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDerivationAlgorithm {
    Hkdf,
    Pbkdf2,
    Scrypt,
    Argon2,
    Custom(u32),
}

#[derive(Debug, Clone)]
pub struct KeyDerivationParameters {
    /// Salt value
    pub salt: Vec<u8>,
    
    /// Iteration count
    pub iterations: Option<u32>,
    
    /// Memory cost (for memory-hard functions)
    pub memory_cost: Option<u32>,
    
    /// Parallelism factor
    pub parallelism: Option<u32>,
    
    /// Output length
    pub output_length: u32,
    
    /// Additional parameters
    pub additional_params: HashMap<String, ParameterValue>,
}

#[derive(Debug, Clone)]
pub struct KeyProtectionInfo {
    /// Protection method
    pub method: KeyProtectionMethod,
    
    /// Encryption algorithm (if encrypted)
    pub encryption_algorithm: Option<AlgorithmIdentifier>,
    
    /// Key derivation for protection key
    pub key_derivation: Option<KeyDerivationInfo>,
    
    /// Authentication tag (if authenticated)
    pub auth_tag: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtectionMethod {
    /// No protection (plaintext)
    None,
    
    /// Password-based encryption
    PasswordBased,
    
    /// Key-based encryption
    KeyBased,
    
    /// Hardware security module
    Hsm,
    
    /// Secure enclave
    SecureEnclave,
}
```

### Signature Section

```rust
/// Signature section data structure
#[derive(Debug, Clone)]
pub struct SignatureSection {
    /// Signature algorithm
    pub algorithm: AlgorithmIdentifier,
    
    /// Signature format
    pub format: SignatureFormat,
    
    /// Signature data
    pub signature_data: Vec<u8>,
    
    /// Signer information
    pub signer_info: SignerInfo,
    
    /// Signed attributes
    pub signed_attributes: Option<Vec<SignedAttribute>>,
    
    /// Unsigned attributes
    pub unsigned_attributes: Option<Vec<UnsignedAttribute>>,
    
    /// Timestamp information
    pub timestamp_info: Option<TimestampInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFormat {
    /// Raw signature bytes
    Raw,
    
    /// ASN.1 DER encoded
    Asn1Der,
    
    /// PKCS#7/CMS format
    Pkcs7,
    
    /// JSON Web Signature
    Jws,
    
    /// OpenPGP signature
    OpenPgp,
    
    /// Quantum-safe signature format
    QuantumSafe,
}

#[derive(Debug, Clone)]
pub struct SignerInfo {
    /// Signer identifier
    pub signer_id: SignerId,
    
    /// Signer certificate (if available)
    pub certificate: Option<Vec<u8>>,
    
    /// Signature creation time
    pub signing_time: Option<u64>,
    
    /// Signer location
    pub location: Option<String>,
    
    /// Signer role
    pub role: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SignerId {
    /// Certificate subject key identifier
    SubjectKeyId(Vec<u8>),
    
    /// Certificate issuer and serial number
    IssuerAndSerial {
        issuer: Vec<u8>,
        serial: Vec<u8>,
    },
    
    /// Direct key identifier
    KeyId(String),
    
    /// Custom identifier
    Custom(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct SignedAttribute {
    /// Attribute OID
    pub oid: String,
    
    /// Attribute value
    pub value: Vec<u8>,
    
    /// Attribute criticality
    pub critical: bool,
}

#[derive(Debug, Clone)]
pub struct UnsignedAttribute {
    /// Attribute OID
    pub oid: String,
    
    /// Attribute value
    pub value: Vec<u8>,
}
```

## Encryption and Compression

### Encryption Support

```rust
/// Encryption information for encrypted sections
#[derive(Debug, Clone)]
pub struct EncryptionInfo {
    /// Encryption algorithm
    pub algorithm: EncryptionAlgorithm,
    
    /// Key derivation method
    pub key_derivation: KeyDerivationMethod,
    
    /// Initialization vector/nonce
    pub iv: Vec<u8>,
    
    /// Authentication tag (for AEAD)
    pub auth_tag: Option<Vec<u8>>,
    
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    
    /// Recipient information
    pub recipients: Vec<RecipientInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    Aes256Gcm,
    
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    
    /// AES-256-CBC with HMAC-SHA256
    Aes256CbcHmacSha256,
    
    /// Quantum-safe symmetric encryption
    QuantumSafeSymmetric,
}

#[derive(Debug, Clone)]
pub enum KeyDerivationMethod {
    /// Direct key (no derivation)
    Direct,
    
    /// Password-based key derivation
    PasswordBased {
        algorithm: KeyDerivationAlgorithm,
        parameters: KeyDerivationParameters,
    },
    
    /// Key encapsulation mechanism
    Kem {
        algorithm: AlgorithmIdentifier,
        ciphertext: Vec<u8>,
    },
    
    /// Key agreement
    KeyAgreement {
        algorithm: AlgorithmIdentifier,
        public_key: Vec<u8>,
    },
}

#[derive(Debug, Clone)]
pub struct RecipientInfo {
    /// Recipient identifier
    pub recipient_id: RecipientId,
    
    /// Key encryption method
    pub key_encryption: KeyEncryptionInfo,
    
    /// Encrypted content encryption key
    pub encrypted_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum RecipientId {
    /// Certificate-based recipient
    Certificate {
        issuer: Vec<u8>,
        serial: Vec<u8>,
    },
    
    /// Key identifier-based recipient
    KeyId(String),
    
    /// Password-based recipient
    Password {
        salt: Vec<u8>,
        iterations: u32,
    },
}

#[derive(Debug, Clone)]
pub struct KeyEncryptionInfo {
    /// Key encryption algorithm
    pub algorithm: AlgorithmIdentifier,
    
    /// Algorithm parameters
    pub parameters: Option<Vec<u8>>,
}
```

### Compression Support

```rust
/// Compression information for compressed sections
#[derive(Debug, Clone)]
pub struct CompressionInfo {
    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,
    
    /// Original size before compression
    pub original_size: u64,
    
    /// Compressed size
    pub compressed_size: u64,
    
    /// Compression parameters
    pub parameters: CompressionParameters,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    
    /// DEFLATE (RFC 1951)
    Deflate,
    
    /// GZIP (RFC 1952)
    Gzip,
    
    /// Brotli
    Brotli,
    
    /// LZ4
    Lz4,
    
    /// Zstandard
    Zstd,
    
    /// LZMA
    Lzma,
}

#[derive(Debug, Clone)]
pub struct CompressionParameters {
    /// Compression level (algorithm-specific)
    pub level: Option<u32>,
    
    /// Window size (for algorithms that support it)
    pub window_size: Option<u32>,
    
    /// Dictionary (for algorithms that support it)
    pub dictionary: Option<Vec<u8>>,
    
    /// Additional parameters
    pub additional_params: HashMap<String, ParameterValue>,
}
```

## File Operations

### Reading QSFF Files

```rust
/// QSFF file reader
pub struct QsffReader<R: Read + Seek> {
    reader: R,
    header: QsffFileHeader,
    metadata: Option<QsffMetadata>,
    manifest: Option<AlgorithmManifest>,
    sections: Vec<SectionInfo>,
}

impl<R: Read + Seek> QsffReader<R> {
    /// Open a QSFF file for reading
    pub fn new(mut reader: R) -> Result<Self, QsffError> {
        // Read and validate file header
        let mut header_bytes = [0u8; std::mem::size_of::<QsffFileHeader>()];
        reader.read_exact(&mut header_bytes)?;
        
        let header: QsffFileHeader = unsafe {
            std::mem::transmute(header_bytes)
        };
        header.validate()?;
        
        // Read section information
        let sections = Self::read_section_info(&mut reader, &header)?;
        
        Ok(QsffReader {
            reader,
            header,
            metadata: None,
            manifest: None,
            sections,
        })
    }
    
    /// Read file metadata
    pub fn read_metadata(&mut self) -> Result<&QsffMetadata, QsffError> {
        if self.metadata.is_none() {
            self.reader.seek(SeekFrom::Start(self.header.metadata_offset as u64))?;
            
            let mut metadata_header_bytes = [0u8; std::mem::size_of::<MetadataHeader>()];
            self.reader.read_exact(&mut metadata_header_bytes)?;
            
            let metadata_header: MetadataHeader = unsafe {
                std::mem::transmute(metadata_header_bytes)
            };
            
            // Read metadata content
            let mut metadata_bytes = vec![0u8; metadata_header.section_size as usize - std::mem::size_of::<MetadataHeader>()];
            self.reader.read_exact(&mut metadata_bytes)?;
            
            // Verify checksum
            if !self.verify_metadata_checksum(&metadata_header, &metadata_bytes) {
                return Err(QsffError::ChecksumMismatch);
            }
            
            // Deserialize metadata
            let metadata = self.deserialize_metadata(&metadata_header, &metadata_bytes)?;
            self.metadata = Some(metadata);
        }
        
        Ok(self.metadata.as_ref().unwrap())
    }
    
    /// Read algorithm manifest
    pub fn read_manifest(&mut self) -> Result<&AlgorithmManifest, QsffError> {
        if self.manifest.is_none() {
            self.reader.seek(SeekFrom::Start(self.header.manifest_offset as u64))?;
            
            let mut manifest_header_bytes = [0u8; std::mem::size_of::<ManifestHeader>()];
            self.reader.read_exact(&mut manifest_header_bytes)?;
            
            let manifest_header: ManifestHeader = unsafe {
                std::mem::transmute(manifest_header_bytes)
            };
            
            // Read manifest content
            let mut manifest_bytes = vec![0u8; manifest_header.section_size as usize - std::mem::size_of::<ManifestHeader>()];
            self.reader.read_exact(&mut manifest_bytes)?;
            
            // Verify checksum
            if !self.verify_manifest_checksum(&manifest_header, &manifest_bytes) {
                return Err(QsffError::ChecksumMismatch);
            }
            
            // Deserialize manifest
            let manifest = self.deserialize_manifest(&manifest_header, &manifest_bytes)?;
            self.manifest = Some(manifest);
        }
        
        Ok(self.manifest.as_ref().unwrap())
    }
    
    /// Read a specific section
    pub fn read_section(&mut self, section_index: usize) -> Result<Vec<u8>, QsffError> {
        if section_index >= self.sections.len() {
            return Err(QsffError::InvalidSectionIndex(section_index));
        }
        
        let section_info = &self.sections[section_index];
        
        // Seek to section
        self.reader.seek(SeekFrom::Start(section_info.offset))?;
        
        // Read section header
        let mut header_bytes = [0u8; std::mem::size_of::<SectionHeader>()];
        self.reader.read_exact(&mut header_bytes)?;
        
        let section_header: SectionHeader = unsafe {
            std::mem::transmute(header_bytes)
        };
        
        // Read section data
        let mut section_data = vec![0u8; section_header.data_size as usize];
        self.reader.read_exact(&mut section_data)?;
        
        // Verify checksum
        if !section_header.verify_checksum(&section_data) {
            return Err(QsffError::ChecksumMismatch);
        }
        
        // Decrypt if necessary
        if (section_header.flags & SECTION_FLAG_ENCRYPTED) != 0 {
            section_data = self.decrypt_section_data(&section_data, &section_header)?;
        }
        
        // Decompress if necessary
        if (section_header.flags & SECTION_FLAG_COMPRESSED) != 0 {
            section_data = self.decompress_section_data(&section_data, &section_header)?;
        }
        
        Ok(section_data)
    }
    
    /// List all sections in the file
    pub fn list_sections(&self) -> &[SectionInfo] {
        &self.sections
    }
    
    /// Get file header information
    pub fn header(&self) -> &QsffFileHeader {
        &self.header
    }
}

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub section_type: SectionType,
    pub offset: u64,
    pub size: u32,
    pub flags: u32,
}

const SECTION_FLAG_ENCRYPTED: u32 = 0x0001;
const SECTION_FLAG_COMPRESSED: u32 = 0x0002;
const SECTION_FLAG_SIGNED: u32 = 0x0004;
```

### Writing QSFF Files

```rust
/// QSFF file writer
pub struct QsffWriter<W: Write + Seek> {
    writer: W,
    header: QsffFileHeader,
    metadata: Option<QsffMetadata>,
    manifest: Option<AlgorithmManifest>,
    sections: Vec<SectionData>,
    encryption_info: Option<EncryptionInfo>,
    compression_info: Option<CompressionInfo>,
}

impl<W: Write + Seek> QsffWriter<W> {
    /// Create a new QSFF file writer
    pub fn new(writer: W, version: QsffVersion) -> Self {
        let mut header = QsffFileHeader::new(version);
        header.flags.set_flag(QsffFlags::QUANTUM_SAFE);
        
        QsffWriter {
            writer,
            header,
            metadata: None,
            manifest: None,
            sections: Vec::new(),
            encryption_info: None,
            compression_info: None,
        }
    }
    
    /// Set file metadata
    pub fn set_metadata(&mut self, metadata: QsffMetadata) {
        self.metadata = Some(metadata);
    }
    
    /// Set algorithm manifest
    pub fn set_manifest(&mut self, manifest: AlgorithmManifest) {
        self.manifest = Some(manifest);
    }
    
    /// Add a section to the file
    pub fn add_section(&mut self, section_type: SectionType, data: Vec<u8>) -> Result<usize, QsffError> {
        let section_index = self.sections.len();
        
        let section_data = SectionData {
            section_type,
            data,
            flags: 0,
        };
        
        self.sections.push(section_data);
        Ok(section_index)
    }
    
    /// Enable encryption for the file
    pub fn enable_encryption(&mut self, encryption_info: EncryptionInfo) {
        self.encryption_info = Some(encryption_info);
        self.header.flags.set_flag(QsffFlags::ENCRYPTED);
    }
    
    /// Enable compression for the file
    pub fn enable_compression(&mut self, compression_info: CompressionInfo) {
        self.compression_info = Some(compression_info);
        self.header.flags.set_flag(QsffFlags::COMPRESSED);
    }
    
    /// Finalize and write the file
    pub fn finalize(mut self) -> Result<(), QsffError> {
        // Calculate offsets
        let mut current_offset = std::mem::size_of::<QsffFileHeader>() as u32;
        
        // Metadata offset
        self.header.metadata_offset = current_offset;
        if let Some(ref metadata) = self.metadata {
            current_offset += self.calculate_metadata_size(metadata);
        }
        
        // Manifest offset
        self.header.manifest_offset = current_offset;
        if let Some(ref manifest) = self.manifest {
            current_offset += self.calculate_manifest_size(manifest);
        }
        
        // Content offset
        self.header.content_offset = current_offset;
        for section in &self.sections {
            current_offset += std::mem::size_of::<SectionHeader>() as u32;
            current_offset += section.data.len() as u32;
        }
        
        // Signature offset (if signed)
        self.header.signature_offset = current_offset;
        
        // File size
        self.header.file_size = current_offset as u64 + std::mem::size_of::<QsffFileFooter>() as u64;
        self.header.section_count = self.sections.len() as u32;
        
        // Write file header
        self.write_header()?;
        
        // Write metadata
        if let Some(metadata) = self.metadata {
            self.write_metadata(&metadata)?;
        }
        
        // Write manifest
        if let Some(manifest) = self.manifest {
            self.write_manifest(&manifest)?;
        }
        
        // Write sections
        self.write_sections()?;
        
        // Write signature block (if applicable)
        if self.header.flags.has_flag(QsffFlags::SIGNED) {
            self.write_signature_block()?;
        }
        
        // Write file footer
        self.write_footer()?;
        
        Ok(())
    }
    
    fn write_header(&mut self) -> Result<(), QsffError> {
        let header_bytes: [u8; std::mem::size_of::<QsffFileHeader>()] = unsafe {
            std::mem::transmute(self.header)
        };
        self.writer.write_all(&header_bytes)?;
        Ok(())
    }
    
    fn write_sections(&mut self) -> Result<(), QsffError> {
        for section in &self.sections {
            let mut section_data = section.data.clone();
            let mut flags = section.flags;
            
            // Compress if enabled
            if let Some(ref compression_info) = self.compression_info {
                section_data = self.compress_data(&section_data, compression_info)?;
                flags |= SECTION_FLAG_COMPRESSED;
            }
            
            // Encrypt if enabled
            if let Some(ref encryption_info) = self.encryption_info {
                section_data = self.encrypt_data(&section_data, encryption_info)?;
                flags |= SECTION_FLAG_ENCRYPTED;
            }
            
            // Create section header
            let mut section_header = SectionHeader::new(section.section_type, section_data.len() as u32);
            section_header.flags = flags;
            section_header.calculate_checksum(&section_data);
            
            // Write section header
            let header_bytes: [u8; std::mem::size_of::<SectionHeader>()] = unsafe {
                std::mem::transmute(section_header)
            };
            self.writer.write_all(&header_bytes)?;
            
            // Write section data
            self.writer.write_all(&section_data)?;
        }
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct SectionData {
    section_type: SectionType,
    data: Vec<u8>,
    flags: u32,
}
```

## File Footer

```rust
/// QSFF file footer structure (32 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct QsffFileFooter {
    /// File integrity hash
    pub file_hash: [u8; 32],
}

impl QsffFileFooter {
    pub fn new() -> Self {
        QsffFileFooter {
            file_hash: [0u8; 32],
        }
    }
    
    pub fn calculate_file_hash<R: Read + Seek>(&mut self, reader: &mut R) -> Result<(), QsffError> {
        use sha2::{Sha256, Digest};
        
        // Seek to beginning of file
        reader.seek(SeekFrom::Start(0))?;
        
        // Read entire file except footer
        let file_size = reader.seek(SeekFrom::End(0))? - std::mem::size_of::<QsffFileFooter>() as u64;
        reader.seek(SeekFrom::Start(0))?;
        
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        let mut remaining = file_size;
        
        while remaining > 0 {
            let to_read = std::cmp::min(buffer.len() as u64, remaining) as usize;
            let bytes_read = reader.read(&mut buffer[..to_read])?;
            if bytes_read == 0 {
                break;
            }
            hasher.update(&buffer[..bytes_read]);
            remaining -= bytes_read as u64;
        }
        
        self.file_hash = hasher.finalize().into();
        Ok(())
    }
    
    pub fn verify_file_hash<R: Read + Seek>(&self, reader: &mut R) -> Result<bool, QsffError> {
        let mut temp_footer = QsffFileFooter::new();
        temp_footer.calculate_file_hash(reader)?;
        Ok(temp_footer.file_hash == self.file_hash)
    }
}
```

This comprehensive file format specification establishes QSFF as a robust, quantum-safe container format with extensive metadata, algorithm transparency, and security features.

