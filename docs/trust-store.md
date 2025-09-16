# Quantum Shield Trust Store

## Overview

The Quantum Shield Trust Store is a comprehensive certificate and key management system designed to handle both classical and post-quantum cryptographic identities. It provides secure storage, validation, and management of digital certificates, public keys, and trust relationships in a quantum-safe environment.

## Trust Store Architecture

### Core Components

```rust
pub struct QuantumTrustStore {
    /// Certificate storage backend
    storage: Box<dyn TrustStoreStorage>,
    
    /// Certificate validation engine
    validator: CertificateValidator,
    
    /// Revocation checking service
    revocation_checker: RevocationChecker,
    
    /// Trust policy engine
    trust_policy: TrustPolicyEngine,
    
    /// Certificate cache for performance
    cache: Arc<RwLock<CertificateCache>>,
    
    /// Audit logger for security events
    audit_logger: AuditLogger,
}

/// Trust store configuration
#[derive(Debug, Clone)]
pub struct TrustStoreConfig {
    /// Storage backend configuration
    pub storage_config: StorageConfig,
    
    /// Certificate validation settings
    pub validation_config: ValidationConfig,
    
    /// Revocation checking settings
    pub revocation_config: RevocationConfig,
    
    /// Trust policy configuration
    pub trust_policy_config: TrustPolicyConfig,
    
    /// Performance and caching settings
    pub cache_config: CacheConfig,
    
    /// Security and audit settings
    pub security_config: SecurityConfig,
}
```

### Trust Hierarchy

```rust
/// Trust levels in the quantum-safe trust hierarchy
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Untrusted - explicitly distrusted
    Untrusted = 0,
    
    /// Unknown - no trust information available
    Unknown = 1,
    
    /// Conditional - limited trust with restrictions
    Conditional = 2,
    
    /// Trusted - standard trust level
    Trusted = 3,
    
    /// Highly Trusted - elevated trust level
    HighlyTrusted = 4,
    
    /// Root Authority - ultimate trust anchor
    RootAuthority = 5,
}

/// Trust anchor representing a root of trust
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Unique identifier for the trust anchor
    pub id: TrustAnchorId,
    
    /// Human-readable name
    pub name: String,
    
    /// Root certificate or public key
    pub root_certificate: Certificate,
    
    /// Trust level assigned to this anchor
    pub trust_level: TrustLevel,
    
    /// Validity period for this trust anchor
    pub validity_period: ValidityPeriod,
    
    /// Supported algorithms and parameters
    pub supported_algorithms: Vec<AlgorithmIdentifier>,
    
    /// Trust anchor metadata
    pub metadata: TrustAnchorMetadata,
}

/// Certificate trust information
#[derive(Debug, Clone)]
pub struct CertificateTrust {
    /// Certificate identifier
    pub certificate_id: CertificateId,
    
    /// Current trust level
    pub trust_level: TrustLevel,
    
    /// Trust path to root anchor
    pub trust_path: Vec<CertificateId>,
    
    /// Trust establishment timestamp
    pub established_at: SystemTime,
    
    /// Trust expiration (if any)
    pub expires_at: Option<SystemTime>,
    
    /// Trust establishment reason
    pub establishment_reason: TrustEstablishmentReason,
    
    /// Trust constraints and limitations
    pub constraints: Vec<TrustConstraint>,
}
```

## Certificate Management

### Certificate Storage

```rust
/// Certificate storage interface
pub trait TrustStoreStorage: Send + Sync {
    /// Store a certificate in the trust store
    async fn store_certificate(&mut self, certificate: &Certificate) -> Result<CertificateId, TrustStoreError>;
    
    /// Retrieve certificate by ID
    async fn get_certificate(&self, id: &CertificateId) -> Result<Option<Certificate>, TrustStoreError>;
    
    /// Find certificates by subject
    async fn find_certificates_by_subject(&self, subject: &DistinguishedName) -> Result<Vec<Certificate>, TrustStoreError>;
    
    /// Find certificates by issuer
    async fn find_certificates_by_issuer(&self, issuer: &DistinguishedName) -> Result<Vec<Certificate>, TrustStoreError>;
    
    /// Find certificates by key identifier
    async fn find_certificates_by_key_id(&self, key_id: &KeyIdentifier) -> Result<Vec<Certificate>, TrustStoreError>;
    
    /// Update certificate trust information
    async fn update_certificate_trust(&mut self, id: &CertificateId, trust: &CertificateTrust) -> Result<(), TrustStoreError>;
    
    /// Delete certificate from storage
    async fn delete_certificate(&mut self, id: &CertificateId) -> Result<(), TrustStoreError>;
    
    /// List all certificates with optional filtering
    async fn list_certificates(&self, filter: Option<&CertificateFilter>) -> Result<Vec<CertificateId>, TrustStoreError>;
}

/// SQLite-based trust store implementation
pub struct SqliteTrustStore {
    connection_pool: Pool<SqliteConnectionManager>,
    encryption_key: Option<[u8; 32]>,
}

impl SqliteTrustStore {
    pub async fn new(database_path: &str, encryption_key: Option<[u8; 32]>) -> Result<Self, TrustStoreError> {
        let manager = SqliteConnectionManager::file(database_path);
        let pool = Pool::new(manager)?;
        
        let store = SqliteTrustStore {
            connection_pool: pool,
            encryption_key,
        };
        
        // Initialize database schema
        store.initialize_schema().await?;
        
        Ok(store)
    }
    
    async fn initialize_schema(&self) -> Result<(), TrustStoreError> {
        let conn = self.connection_pool.get().await?;
        
        conn.execute_batch(r#"
            -- Certificates table
            CREATE TABLE IF NOT EXISTS certificates (
                id TEXT PRIMARY KEY,
                subject_dn TEXT NOT NULL,
                issuer_dn TEXT NOT NULL,
                serial_number TEXT NOT NULL,
                not_before INTEGER NOT NULL,
                not_after INTEGER NOT NULL,
                public_key_algorithm TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                certificate_data BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            
            -- Certificate trust information
            CREATE TABLE IF NOT EXISTS certificate_trust (
                certificate_id TEXT PRIMARY KEY,
                trust_level INTEGER NOT NULL,
                trust_path TEXT, -- JSON array of certificate IDs
                established_at INTEGER NOT NULL,
                expires_at INTEGER,
                establishment_reason TEXT NOT NULL,
                constraints TEXT, -- JSON array of constraints
                FOREIGN KEY (certificate_id) REFERENCES certificates(id)
            );
            
            -- Trust anchors
            CREATE TABLE IF NOT EXISTS trust_anchors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                certificate_id TEXT NOT NULL,
                trust_level INTEGER NOT NULL,
                validity_start INTEGER NOT NULL,
                validity_end INTEGER NOT NULL,
                supported_algorithms TEXT, -- JSON array
                metadata TEXT, -- JSON object
                created_at INTEGER NOT NULL,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id)
            );
            
            -- Certificate revocation information
            CREATE TABLE IF NOT EXISTS certificate_revocation (
                certificate_id TEXT PRIMARY KEY,
                revocation_status INTEGER NOT NULL,
                revocation_time INTEGER,
                revocation_reason INTEGER,
                crl_url TEXT,
                ocsp_url TEXT,
                last_checked INTEGER NOT NULL,
                next_check INTEGER,
                FOREIGN KEY (certificate_id) REFERENCES certificates(id)
            );
            
            -- Indexes for performance
            CREATE INDEX IF NOT EXISTS idx_certificates_subject ON certificates(subject_dn);
            CREATE INDEX IF NOT EXISTS idx_certificates_issuer ON certificates(issuer_dn);
            CREATE INDEX IF NOT EXISTS idx_certificates_serial ON certificates(serial_number);
            CREATE INDEX IF NOT EXISTS idx_certificate_trust_level ON certificate_trust(trust_level);
            CREATE INDEX IF NOT EXISTS idx_revocation_status ON certificate_revocation(revocation_status);
        "#)?;
        
        Ok(())
    }
}

impl TrustStoreStorage for SqliteTrustStore {
    async fn store_certificate(&mut self, certificate: &Certificate) -> Result<CertificateId, TrustStoreError> {
        let cert_id = CertificateId::from_certificate(certificate)?;
        let conn = self.connection_pool.get().await?;
        
        // Encrypt certificate data if encryption is enabled
        let cert_data = if let Some(key) = &self.encryption_key {
            encrypt_certificate_data(&certificate.to_der()?, key)?
        } else {
            certificate.to_der()?
        };
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        
        conn.execute(
            r#"
            INSERT OR REPLACE INTO certificates 
            (id, subject_dn, issuer_dn, serial_number, not_before, not_after, 
             public_key_algorithm, signature_algorithm, certificate_data, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            params![
                cert_id.to_string(),
                certificate.subject().to_string(),
                certificate.issuer().to_string(),
                certificate.serial_number().to_string(),
                certificate.not_before().timestamp(),
                certificate.not_after().timestamp(),
                certificate.public_key_algorithm().to_string(),
                certificate.signature_algorithm().to_string(),
                cert_data,
                now,
                now,
            ],
        )?;
        
        Ok(cert_id)
    }
    
    async fn get_certificate(&self, id: &CertificateId) -> Result<Option<Certificate>, TrustStoreError> {
        let conn = self.connection_pool.get().await?;
        
        let mut stmt = conn.prepare(
            "SELECT certificate_data FROM certificates WHERE id = ?1"
        )?;
        
        let cert_data: Option<Vec<u8>> = stmt.query_row(
            params![id.to_string()],
            |row| Ok(row.get(0)?),
        ).optional()?;
        
        if let Some(data) = cert_data {
            // Decrypt certificate data if encryption is enabled
            let decrypted_data = if let Some(key) = &self.encryption_key {
                decrypt_certificate_data(&data, key)?
            } else {
                data
            };
            
            let certificate = Certificate::from_der(&decrypted_data)?;
            Ok(Some(certificate))
        } else {
            Ok(None)
        }
    }
    
    async fn find_certificates_by_subject(&self, subject: &DistinguishedName) -> Result<Vec<Certificate>, TrustStoreError> {
        let conn = self.connection_pool.get().await?;
        
        let mut stmt = conn.prepare(
            "SELECT certificate_data FROM certificates WHERE subject_dn = ?1"
        )?;
        
        let rows = stmt.query_map(
            params![subject.to_string()],
            |row| {
                let data: Vec<u8> = row.get(0)?;
                Ok(data)
            },
        )?;
        
        let mut certificates = Vec::new();
        for row in rows {
            let data = row?;
            
            // Decrypt if necessary
            let decrypted_data = if let Some(key) = &self.encryption_key {
                decrypt_certificate_data(&data, key)?
            } else {
                data
            };
            
            let certificate = Certificate::from_der(&decrypted_data)?;
            certificates.push(certificate);
        }
        
        Ok(certificates)
    }
}
```

### Certificate Validation

```rust
/// Certificate validation engine
pub struct CertificateValidator {
    /// Validation configuration
    config: ValidationConfig,
    
    /// Supported algorithms and their validators
    algorithm_validators: HashMap<AlgorithmIdentifier, Box<dyn AlgorithmValidator>>,
    
    /// Certificate chain builder
    chain_builder: CertificateChainBuilder,
    
    /// Time validation service
    time_validator: TimeValidator,
}

impl CertificateValidator {
    pub fn new(config: ValidationConfig) -> Self {
        let mut algorithm_validators: HashMap<AlgorithmIdentifier, Box<dyn AlgorithmValidator>> = HashMap::new();
        
        // Register classical algorithm validators
        algorithm_validators.insert(
            AlgorithmIdentifier::RsaPss,
            Box::new(RsaPssValidator::new()),
        );
        algorithm_validators.insert(
            AlgorithmIdentifier::EcdsaP256,
            Box::new(EcdsaValidator::new(EcdsaCurve::P256)),
        );
        algorithm_validators.insert(
            AlgorithmIdentifier::Ed25519,
            Box::new(Ed25519Validator::new()),
        );
        
        // Register post-quantum algorithm validators
        algorithm_validators.insert(
            AlgorithmIdentifier::MlDsa44,
            Box::new(MlDsaValidator::new(MlDsaParameterSet::ML_DSA_44)),
        );
        algorithm_validators.insert(
            AlgorithmIdentifier::MlDsa65,
            Box::new(MlDsaValidator::new(MlDsaParameterSet::ML_DSA_65)),
        );
        algorithm_validators.insert(
            AlgorithmIdentifier::MlDsa87,
            Box::new(MlDsaValidator::new(MlDsaParameterSet::ML_DSA_87)),
        );
        algorithm_validators.insert(
            AlgorithmIdentifier::Falcon512,
            Box::new(FalconValidator::new(FalconParameterSet::Falcon512)),
        );
        algorithm_validators.insert(
            AlgorithmIdentifier::SphincsShake256f,
            Box::new(SphincsValidator::new(SphincsParameterSet::SphincsShake256f)),
        );
        
        CertificateValidator {
            config,
            algorithm_validators,
            chain_builder: CertificateChainBuilder::new(),
            time_validator: TimeValidator::new(),
        }
    }
    
    /// Validate a certificate and its chain
    pub async fn validate_certificate(
        &self,
        certificate: &Certificate,
        trust_store: &QuantumTrustStore,
    ) -> Result<ValidationResult, ValidationError> {
        let mut validation_result = ValidationResult::new(certificate.id());
        
        // 1. Basic certificate structure validation
        self.validate_certificate_structure(certificate, &mut validation_result)?;
        
        // 2. Time validity validation
        self.validate_time_validity(certificate, &mut validation_result)?;
        
        // 3. Algorithm validation
        self.validate_algorithms(certificate, &mut validation_result)?;
        
        // 4. Certificate chain validation
        let chain = self.build_certificate_chain(certificate, trust_store).await?;
        self.validate_certificate_chain(&chain, trust_store, &mut validation_result).await?;
        
        // 5. Revocation status validation
        self.validate_revocation_status(certificate, trust_store, &mut validation_result).await?;
        
        // 6. Policy validation
        self.validate_certificate_policies(certificate, &chain, &mut validation_result)?;
        
        // 7. Key usage validation
        self.validate_key_usage(certificate, &mut validation_result)?;
        
        Ok(validation_result)
    }
    
    fn validate_certificate_structure(
        &self,
        certificate: &Certificate,
        result: &mut ValidationResult,
    ) -> Result<(), ValidationError> {
        // Check certificate version
        if certificate.version() != CertificateVersion::V3 {
            result.add_error(ValidationError::UnsupportedVersion(certificate.version()));
        }
        
        // Validate subject and issuer
        if certificate.subject().is_empty() {
            result.add_error(ValidationError::EmptySubject);
        }
        
        if certificate.issuer().is_empty() {
            result.add_error(ValidationError::EmptyIssuer);
        }
        
        // Validate serial number
        if certificate.serial_number().is_zero() {
            result.add_warning(ValidationWarning::ZeroSerialNumber);
        }
        
        // Validate extensions
        self.validate_extensions(certificate, result)?;
        
        Ok(())
    }
    
    fn validate_time_validity(
        &self,
        certificate: &Certificate,
        result: &mut ValidationResult,
    ) -> Result<(), ValidationError> {
        let now = self.time_validator.current_time();
        
        if certificate.not_before() > now {
            result.add_error(ValidationError::CertificateNotYetValid {
                not_before: certificate.not_before(),
                current_time: now,
            });
        }
        
        if certificate.not_after() < now {
            result.add_error(ValidationError::CertificateExpired {
                not_after: certificate.not_after(),
                current_time: now,
            });
        }
        
        // Check for certificates expiring soon
        let warning_threshold = Duration::from_secs(30 * 24 * 3600); // 30 days
        if certificate.not_after() - now < warning_threshold {
            result.add_warning(ValidationWarning::CertificateExpiringSoon {
                not_after: certificate.not_after(),
                current_time: now,
            });
        }
        
        Ok(())
    }
    
    fn validate_algorithms(
        &self,
        certificate: &Certificate,
        result: &mut ValidationResult,
    ) -> Result<(), ValidationError> {
        let sig_alg = certificate.signature_algorithm();
        let pk_alg = certificate.public_key_algorithm();
        
        // Check if algorithms are supported
        if !self.algorithm_validators.contains_key(&sig_alg) {
            result.add_error(ValidationError::UnsupportedSignatureAlgorithm(sig_alg));
        }
        
        if !self.algorithm_validators.contains_key(&pk_alg) {
            result.add_error(ValidationError::UnsupportedPublicKeyAlgorithm(pk_alg));
        }
        
        // Check algorithm compatibility
        if !self.are_algorithms_compatible(&sig_alg, &pk_alg) {
            result.add_error(ValidationError::IncompatibleAlgorithms {
                signature_algorithm: sig_alg,
                public_key_algorithm: pk_alg,
            });
        }
        
        // Check quantum safety
        let quantum_safe_sig = self.is_quantum_safe_algorithm(&sig_alg);
        let quantum_safe_pk = self.is_quantum_safe_algorithm(&pk_alg);
        
        if !quantum_safe_sig || !quantum_safe_pk {
            result.add_warning(ValidationWarning::NotQuantumSafe {
                signature_quantum_safe: quantum_safe_sig,
                public_key_quantum_safe: quantum_safe_pk,
            });
        }
        
        Ok(())
    }
    
    async fn validate_certificate_chain(
        &self,
        chain: &CertificateChain,
        trust_store: &QuantumTrustStore,
        result: &mut ValidationResult,
    ) -> Result<(), ValidationError> {
        // Validate each certificate in the chain
        for (i, certificate) in chain.certificates().iter().enumerate() {
            // Skip validation for the target certificate (already validated)
            if i == 0 {
                continue;
            }
            
            // Validate intermediate/root certificate
            let cert_result = self.validate_certificate_structure(certificate, &mut ValidationResult::new(certificate.id()))?;
            result.merge_intermediate_result(cert_result);
        }
        
        // Validate chain signatures
        for i in 0..chain.certificates().len() - 1 {
            let subject_cert = &chain.certificates()[i];
            let issuer_cert = &chain.certificates()[i + 1];
            
            self.validate_signature(subject_cert, issuer_cert, result)?;
        }
        
        // Validate trust anchor
        let root_cert = chain.root_certificate();
        let trust_anchor = trust_store.find_trust_anchor_for_certificate(root_cert).await?;
        
        if let Some(anchor) = trust_anchor {
            result.set_trust_anchor(anchor);
            result.set_trust_level(anchor.trust_level);
        } else {
            result.add_error(ValidationError::NoTrustAnchor);
        }
        
        Ok(())
    }
    
    fn validate_signature(
        &self,
        subject_cert: &Certificate,
        issuer_cert: &Certificate,
        result: &mut ValidationResult,
    ) -> Result<(), ValidationError> {
        let signature_algorithm = subject_cert.signature_algorithm();
        
        if let Some(validator) = self.algorithm_validators.get(&signature_algorithm) {
            let signature_valid = validator.verify_signature(
                subject_cert.tbs_certificate(),
                subject_cert.signature(),
                issuer_cert.public_key(),
            )?;
            
            if !signature_valid {
                result.add_error(ValidationError::InvalidSignature {
                    subject: subject_cert.subject().clone(),
                    issuer: issuer_cert.subject().clone(),
                });
            }
        } else {
            result.add_error(ValidationError::UnsupportedSignatureAlgorithm(signature_algorithm));
        }
        
        Ok(())
    }
}
```

### Revocation Checking

```rust
/// Certificate revocation checker
pub struct RevocationChecker {
    /// HTTP client for OCSP and CRL requests
    http_client: reqwest::Client,
    
    /// Revocation cache
    cache: Arc<RwLock<RevocationCache>>,
    
    /// Configuration
    config: RevocationConfig,
}

#[derive(Debug, Clone)]
pub struct RevocationConfig {
    /// Enable OCSP checking
    pub ocsp_enabled: bool,
    
    /// Enable CRL checking
    pub crl_enabled: bool,
    
    /// OCSP request timeout
    pub ocsp_timeout: Duration,
    
    /// CRL download timeout
    pub crl_timeout: Duration,
    
    /// Maximum CRL size
    pub max_crl_size: usize,
    
    /// Cache TTL for revocation information
    pub cache_ttl: Duration,
    
    /// Fallback behavior when revocation checking fails
    pub fallback_behavior: RevocationFallbackBehavior,
}

#[derive(Debug, Clone)]
pub enum RevocationFallbackBehavior {
    /// Treat as valid if revocation check fails
    AssumeValid,
    
    /// Treat as revoked if revocation check fails
    AssumeRevoked,
    
    /// Return error if revocation check fails
    RequireCheck,
}

impl RevocationChecker {
    pub fn new(config: RevocationConfig) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(config.ocsp_timeout.max(config.crl_timeout))
            .build()
            .expect("Failed to create HTTP client");
        
        RevocationChecker {
            http_client,
            cache: Arc::new(RwLock::new(RevocationCache::new(config.cache_ttl))),
            config,
        }
    }
    
    /// Check certificate revocation status
    pub async fn check_revocation_status(
        &self,
        certificate: &Certificate,
        issuer_certificate: &Certificate,
    ) -> Result<RevocationStatus, RevocationError> {
        let cert_id = certificate.id();
        
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached_status) = cache.get(&cert_id) {
                if !cached_status.is_expired() {
                    return Ok(cached_status.status);
                }
            }
        }
        
        let mut revocation_status = RevocationStatus::Unknown;
        let mut last_error = None;
        
        // Try OCSP first (more current information)
        if self.config.ocsp_enabled {
            match self.check_ocsp_status(certificate, issuer_certificate).await {
                Ok(status) => {
                    revocation_status = status;
                },
                Err(e) => {
                    last_error = Some(e);
                },
            }
        }
        
        // Fall back to CRL if OCSP failed or returned unknown
        if revocation_status == RevocationStatus::Unknown && self.config.crl_enabled {
            match self.check_crl_status(certificate, issuer_certificate).await {
                Ok(status) => {
                    revocation_status = status;
                },
                Err(e) => {
                    last_error = Some(e);
                },
            }
        }
        
        // Handle fallback behavior
        if revocation_status == RevocationStatus::Unknown {
            revocation_status = match self.config.fallback_behavior {
                RevocationFallbackBehavior::AssumeValid => RevocationStatus::Valid,
                RevocationFallbackBehavior::AssumeRevoked => RevocationStatus::Revoked {
                    revocation_time: SystemTime::now(),
                    reason: RevocationReason::Unspecified,
                },
                RevocationFallbackBehavior::RequireCheck => {
                    return Err(last_error.unwrap_or(RevocationError::CheckFailed));
                },
            };
        }
        
        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert(cert_id, CachedRevocationStatus {
                status: revocation_status.clone(),
                cached_at: SystemTime::now(),
                ttl: self.config.cache_ttl,
            });
        }
        
        Ok(revocation_status)
    }
    
    async fn check_ocsp_status(
        &self,
        certificate: &Certificate,
        issuer_certificate: &Certificate,
    ) -> Result<RevocationStatus, RevocationError> {
        // Extract OCSP URL from certificate
        let ocsp_urls = certificate.ocsp_urls()?;
        if ocsp_urls.is_empty() {
            return Err(RevocationError::NoOcspUrl);
        }
        
        // Build OCSP request
        let ocsp_request = self.build_ocsp_request(certificate, issuer_certificate)?;
        
        // Try each OCSP URL
        for url in &ocsp_urls {
            match self.send_ocsp_request(url, &ocsp_request).await {
                Ok(response) => {
                    return self.parse_ocsp_response(&response, certificate);
                },
                Err(e) => {
                    log::warn!("OCSP request to {} failed: {}", url, e);
                    continue;
                },
            }
        }
        
        Err(RevocationError::AllOcspRequestsFailed)
    }
    
    fn build_ocsp_request(
        &self,
        certificate: &Certificate,
        issuer_certificate: &Certificate,
    ) -> Result<OcspRequest, RevocationError> {
        use ocsp::{OcspRequestBuilder, CertId};
        
        // Create certificate ID
        let cert_id = CertId::new(
            &issuer_certificate.public_key_hash()?,
            &issuer_certificate.subject_key_identifier()?,
            &certificate.serial_number(),
        )?;
        
        // Build OCSP request
        let request = OcspRequestBuilder::new()
            .add_cert_id(cert_id)
            .build()?;
        
        Ok(request)
    }
    
    async fn send_ocsp_request(
        &self,
        url: &str,
        request: &OcspRequest,
    ) -> Result<OcspResponse, RevocationError> {
        let request_der = request.to_der()?;
        
        let response = self.http_client
            .post(url)
            .header("Content-Type", "application/ocsp-request")
            .body(request_der)
            .timeout(self.config.ocsp_timeout)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(RevocationError::HttpError(response.status()));
        }
        
        let response_bytes = response.bytes().await?;
        let ocsp_response = OcspResponse::from_der(&response_bytes)?;
        
        Ok(ocsp_response)
    }
    
    fn parse_ocsp_response(
        &self,
        response: &OcspResponse,
        certificate: &Certificate,
    ) -> Result<RevocationStatus, RevocationError> {
        use ocsp::{OcspResponseStatus, CertStatus};
        
        // Check response status
        if response.status() != OcspResponseStatus::Successful {
            return Err(RevocationError::OcspResponseError(response.status()));
        }
        
        // Extract certificate status
        let basic_response = response.basic_response()?;
        let single_responses = basic_response.single_responses();
        
        for single_response in single_responses {
            if single_response.cert_id().matches_certificate(certificate)? {
                return match single_response.cert_status() {
                    CertStatus::Good => Ok(RevocationStatus::Valid),
                    CertStatus::Revoked { revocation_time, reason } => {
                        Ok(RevocationStatus::Revoked {
                            revocation_time: *revocation_time,
                            reason: (*reason).into(),
                        })
                    },
                    CertStatus::Unknown => Ok(RevocationStatus::Unknown),
                };
            }
        }
        
        Err(RevocationError::CertificateNotFound)
    }
    
    async fn check_crl_status(
        &self,
        certificate: &Certificate,
        issuer_certificate: &Certificate,
    ) -> Result<RevocationStatus, RevocationError> {
        // Extract CRL distribution points
        let crl_urls = certificate.crl_distribution_points()?;
        if crl_urls.is_empty() {
            return Err(RevocationError::NoCrlUrl);
        }
        
        // Try each CRL URL
        for url in &crl_urls {
            match self.download_and_verify_crl(url, issuer_certificate).await {
                Ok(crl) => {
                    return self.check_certificate_in_crl(&crl, certificate);
                },
                Err(e) => {
                    log::warn!("CRL download from {} failed: {}", url, e);
                    continue;
                },
            }
        }
        
        Err(RevocationError::AllCrlDownloadsFailed)
    }
    
    async fn download_and_verify_crl(
        &self,
        url: &str,
        issuer_certificate: &Certificate,
    ) -> Result<CertificateRevocationList, RevocationError> {
        // Download CRL
        let response = self.http_client
            .get(url)
            .timeout(self.config.crl_timeout)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(RevocationError::HttpError(response.status()));
        }
        
        let crl_bytes = response.bytes().await?;
        
        // Check size limit
        if crl_bytes.len() > self.config.max_crl_size {
            return Err(RevocationError::CrlTooLarge(crl_bytes.len(), self.config.max_crl_size));
        }
        
        // Parse CRL
        let crl = CertificateRevocationList::from_der(&crl_bytes)?;
        
        // Verify CRL signature
        if !self.verify_crl_signature(&crl, issuer_certificate)? {
            return Err(RevocationError::InvalidCrlSignature);
        }
        
        // Check CRL validity
        let now = SystemTime::now();
        if crl.this_update() > now {
            return Err(RevocationError::CrlNotYetValid);
        }
        
        if let Some(next_update) = crl.next_update() {
            if next_update < now {
                return Err(RevocationError::CrlExpired);
            }
        }
        
        Ok(crl)
    }
    
    fn check_certificate_in_crl(
        &self,
        crl: &CertificateRevocationList,
        certificate: &Certificate,
    ) -> Result<RevocationStatus, RevocationError> {
        let serial_number = certificate.serial_number();
        
        for revoked_cert in crl.revoked_certificates() {
            if revoked_cert.serial_number() == serial_number {
                return Ok(RevocationStatus::Revoked {
                    revocation_time: revoked_cert.revocation_date(),
                    reason: revoked_cert.reason().unwrap_or(RevocationReason::Unspecified),
                });
            }
        }
        
        Ok(RevocationStatus::Valid)
    }
}
```

## Trust Policy Engine

### Policy Definition

```rust
/// Trust policy engine for making trust decisions
pub struct TrustPolicyEngine {
    /// Policy rules
    policies: Vec<TrustPolicy>,
    
    /// Policy evaluation context
    context: PolicyEvaluationContext,
    
    /// Policy decision cache
    decision_cache: Arc<RwLock<PolicyDecisionCache>>,
}

/// Trust policy rule
#[derive(Debug, Clone)]
pub struct TrustPolicy {
    /// Policy identifier
    pub id: PolicyId,
    
    /// Policy name and description
    pub name: String,
    pub description: String,
    
    /// Policy conditions
    pub conditions: Vec<PolicyCondition>,
    
    /// Policy actions
    pub actions: Vec<PolicyAction>,
    
    /// Policy priority (higher number = higher priority)
    pub priority: u32,
    
    /// Policy status
    pub enabled: bool,
}

/// Policy condition types
#[derive(Debug, Clone)]
pub enum PolicyCondition {
    /// Certificate subject matches pattern
    SubjectMatches(DistinguishedNamePattern),
    
    /// Certificate issuer matches pattern
    IssuerMatches(DistinguishedNamePattern),
    
    /// Certificate algorithm is in allowed list
    AlgorithmAllowed(Vec<AlgorithmIdentifier>),
    
    /// Certificate algorithm is quantum-safe
    QuantumSafeRequired,
    
    /// Certificate key size meets minimum requirement
    MinimumKeySize(u32),
    
    /// Certificate is within validity period
    ValidityPeriodCheck,
    
    /// Certificate chain length constraint
    MaxChainLength(u32),
    
    /// Certificate has required key usage
    RequiredKeyUsage(Vec<KeyUsage>),
    
    /// Certificate has required extended key usage
    RequiredExtendedKeyUsage(Vec<ExtendedKeyUsage>),
    
    /// Certificate revocation status
    RevocationStatusCheck(RevocationStatus),
    
    /// Trust anchor constraint
    TrustAnchorRequired(Vec<TrustAnchorId>),
    
    /// Custom policy condition
    Custom(Box<dyn CustomPolicyCondition>),
}

/// Policy action types
#[derive(Debug, Clone)]
pub enum PolicyAction {
    /// Allow certificate with specified trust level
    Allow(TrustLevel),
    
    /// Deny certificate
    Deny(String), // Reason
    
    /// Require additional verification
    RequireAdditionalVerification(Vec<VerificationRequirement>),
    
    /// Set trust constraints
    SetConstraints(Vec<TrustConstraint>),
    
    /// Log security event
    LogSecurityEvent(SecurityEventLevel),
    
    /// Send notification
    SendNotification(NotificationTarget),
    
    /// Custom policy action
    Custom(Box<dyn CustomPolicyAction>),
}

impl TrustPolicyEngine {
    pub fn new(policies: Vec<TrustPolicy>) -> Self {
        TrustPolicyEngine {
            policies,
            context: PolicyEvaluationContext::new(),
            decision_cache: Arc::new(RwLock::new(PolicyDecisionCache::new())),
        }
    }
    
    /// Evaluate trust policies for a certificate
    pub async fn evaluate_trust(
        &self,
        certificate: &Certificate,
        validation_result: &ValidationResult,
        trust_store: &QuantumTrustStore,
    ) -> Result<TrustDecision, PolicyError> {
        let cert_id = certificate.id();
        
        // Check decision cache
        {
            let cache = self.decision_cache.read().await;
            if let Some(cached_decision) = cache.get(&cert_id) {
                if !cached_decision.is_expired() {
                    return Ok(cached_decision.decision.clone());
                }
            }
        }
        
        // Evaluate policies in priority order
        let mut applicable_policies = self.policies.clone();
        applicable_policies.sort_by(|a, b| b.priority.cmp(&a.priority));
        
        let mut decision = TrustDecision::default();
        let mut evaluation_context = PolicyEvaluationContext::new();
        evaluation_context.set_certificate(certificate.clone());
        evaluation_context.set_validation_result(validation_result.clone());
        
        for policy in &applicable_policies {
            if !policy.enabled {
                continue;
            }
            
            // Check if policy conditions are met
            let conditions_met = self.evaluate_conditions(&policy.conditions, &evaluation_context, trust_store).await?;
            
            if conditions_met {
                // Apply policy actions
                for action in &policy.actions {
                    self.apply_policy_action(action, &mut decision, &evaluation_context).await?;
                }
                
                // If policy results in definitive decision, stop evaluation
                if decision.is_definitive() {
                    break;
                }
            }
        }
        
        // Set default decision if no policies applied
        if decision.trust_level.is_none() {
            decision.trust_level = Some(TrustLevel::Unknown);
            decision.decision_reason = "No applicable trust policies found".to_string();
        }
        
        // Cache the decision
        {
            let mut cache = self.decision_cache.write().await;
            cache.insert(cert_id, CachedTrustDecision {
                decision: decision.clone(),
                cached_at: SystemTime::now(),
                ttl: Duration::from_secs(3600), // 1 hour
            });
        }
        
        Ok(decision)
    }
    
    async fn evaluate_conditions(
        &self,
        conditions: &[PolicyCondition],
        context: &PolicyEvaluationContext,
        trust_store: &QuantumTrustStore,
    ) -> Result<bool, PolicyError> {
        for condition in conditions {
            if !self.evaluate_single_condition(condition, context, trust_store).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    async fn evaluate_single_condition(
        &self,
        condition: &PolicyCondition,
        context: &PolicyEvaluationContext,
        trust_store: &QuantumTrustStore,
    ) -> Result<bool, PolicyError> {
        let certificate = context.certificate();
        
        match condition {
            PolicyCondition::SubjectMatches(pattern) => {
                Ok(pattern.matches(certificate.subject()))
            },
            PolicyCondition::IssuerMatches(pattern) => {
                Ok(pattern.matches(certificate.issuer()))
            },
            PolicyCondition::AlgorithmAllowed(allowed_algorithms) => {
                let sig_alg = certificate.signature_algorithm();
                let pk_alg = certificate.public_key_algorithm();
                Ok(allowed_algorithms.contains(&sig_alg) && allowed_algorithms.contains(&pk_alg))
            },
            PolicyCondition::QuantumSafeRequired => {
                let sig_quantum_safe = self.is_quantum_safe_algorithm(&certificate.signature_algorithm());
                let pk_quantum_safe = self.is_quantum_safe_algorithm(&certificate.public_key_algorithm());
                Ok(sig_quantum_safe && pk_quantum_safe)
            },
            PolicyCondition::MinimumKeySize(min_size) => {
                let key_size = certificate.public_key_size()?;
                Ok(key_size >= *min_size)
            },
            PolicyCondition::ValidityPeriodCheck => {
                let now = SystemTime::now();
                Ok(certificate.not_before() <= now && certificate.not_after() >= now)
            },
            PolicyCondition::MaxChainLength(max_length) => {
                let chain_length = context.validation_result().chain_length();
                Ok(chain_length <= *max_length as usize)
            },
            PolicyCondition::RequiredKeyUsage(required_usage) => {
                let cert_usage = certificate.key_usage()?;
                Ok(required_usage.iter().all(|usage| cert_usage.contains(usage)))
            },
            PolicyCondition::RequiredExtendedKeyUsage(required_ext_usage) => {
                let cert_ext_usage = certificate.extended_key_usage()?;
                Ok(required_ext_usage.iter().all(|usage| cert_ext_usage.contains(usage)))
            },
            PolicyCondition::RevocationStatusCheck(required_status) => {
                let actual_status = context.validation_result().revocation_status();
                Ok(actual_status == *required_status)
            },
            PolicyCondition::TrustAnchorRequired(required_anchors) => {
                if let Some(trust_anchor) = context.validation_result().trust_anchor() {
                    Ok(required_anchors.contains(&trust_anchor.id))
                } else {
                    Ok(false)
                }
            },
            PolicyCondition::Custom(custom_condition) => {
                custom_condition.evaluate(context, trust_store).await
            },
        }
    }
    
    async fn apply_policy_action(
        &self,
        action: &PolicyAction,
        decision: &mut TrustDecision,
        context: &PolicyEvaluationContext,
    ) -> Result<(), PolicyError> {
        match action {
            PolicyAction::Allow(trust_level) => {
                decision.trust_level = Some(*trust_level);
                decision.allowed = true;
                decision.decision_reason = format!("Allowed by policy with trust level {:?}", trust_level);
            },
            PolicyAction::Deny(reason) => {
                decision.trust_level = Some(TrustLevel::Untrusted);
                decision.allowed = false;
                decision.decision_reason = reason.clone();
            },
            PolicyAction::RequireAdditionalVerification(requirements) => {
                decision.additional_verification_required.extend(requirements.clone());
            },
            PolicyAction::SetConstraints(constraints) => {
                decision.trust_constraints.extend(constraints.clone());
            },
            PolicyAction::LogSecurityEvent(level) => {
                self.log_security_event(*level, context).await?;
            },
            PolicyAction::SendNotification(target) => {
                self.send_notification(target, context).await?;
            },
            PolicyAction::Custom(custom_action) => {
                custom_action.execute(decision, context).await?;
            },
        }
        
        Ok(())
    }
}
```

## Trust Store Operations

### High-Level API

```rust
impl QuantumTrustStore {
    /// Create a new quantum trust store
    pub async fn new(config: TrustStoreConfig) -> Result<Self, TrustStoreError> {
        let storage = match config.storage_config.backend {
            StorageBackend::Sqlite => {
                Box::new(SqliteTrustStore::new(
                    &config.storage_config.connection_string,
                    config.storage_config.encryption_key,
                ).await?) as Box<dyn TrustStoreStorage>
            },
            StorageBackend::PostgreSQL => {
                Box::new(PostgreSqlTrustStore::new(
                    &config.storage_config.connection_string,
                ).await?) as Box<dyn TrustStoreStorage>
            },
        };
        
        let validator = CertificateValidator::new(config.validation_config);
        let revocation_checker = RevocationChecker::new(config.revocation_config);
        let trust_policy = TrustPolicyEngine::new(config.trust_policy_config.policies);
        let cache = Arc::new(RwLock::new(CertificateCache::new(config.cache_config)));
        let audit_logger = AuditLogger::new(config.security_config.audit_config);
        
        Ok(QuantumTrustStore {
            storage,
            validator,
            revocation_checker,
            trust_policy,
            cache,
            audit_logger,
        })
    }
    
    /// Import a certificate into the trust store
    pub async fn import_certificate(
        &mut self,
        certificate: Certificate,
        initial_trust_level: Option<TrustLevel>,
    ) -> Result<CertificateId, TrustStoreError> {
        // Validate certificate
        let validation_result = self.validator.validate_certificate(&certificate, self).await?;
        
        if !validation_result.is_structurally_valid() {
            return Err(TrustStoreError::InvalidCertificate(validation_result.errors()));
        }
        
        // Store certificate
        let cert_id = self.storage.store_certificate(&certificate).await?;
        
        // Determine trust level
        let trust_level = if let Some(level) = initial_trust_level {
            level
        } else {
            // Evaluate trust policies
            let trust_decision = self.trust_policy.evaluate_trust(&certificate, &validation_result, self).await?;
            trust_decision.trust_level.unwrap_or(TrustLevel::Unknown)
        };
        
        // Store trust information
        let trust_info = CertificateTrust {
            certificate_id: cert_id.clone(),
            trust_level,
            trust_path: validation_result.trust_path().unwrap_or_default(),
            established_at: SystemTime::now(),
            expires_at: None,
            establishment_reason: TrustEstablishmentReason::ManualImport,
            constraints: Vec::new(),
        };
        
        self.storage.update_certificate_trust(&cert_id, &trust_info).await?;
        
        // Log audit event
        self.audit_logger.log_certificate_import(&cert_id, &certificate, trust_level).await?;
        
        Ok(cert_id)
    }
    
    /// Verify a certificate and return trust information
    pub async fn verify_certificate(
        &self,
        certificate: &Certificate,
    ) -> Result<CertificateVerificationResult, TrustStoreError> {
        let cert_id = certificate.id();
        
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached_result) = cache.get_verification_result(&cert_id) {
                if !cached_result.is_expired() {
                    return Ok(cached_result.result.clone());
                }
            }
        }
        
        // Perform full validation
        let validation_result = self.validator.validate_certificate(certificate, self).await?;
        
        // Check revocation status
        let revocation_status = if let Some(issuer_cert) = self.find_issuer_certificate(certificate).await? {
            self.revocation_checker.check_revocation_status(certificate, &issuer_cert).await?
        } else {
            RevocationStatus::Unknown
        };
        
        // Evaluate trust policies
        let trust_decision = self.trust_policy.evaluate_trust(certificate, &validation_result, self).await?;
        
        // Create verification result
        let verification_result = CertificateVerificationResult {
            certificate_id: cert_id.clone(),
            is_valid: validation_result.is_valid() && revocation_status != RevocationStatus::Revoked { .. },
            trust_level: trust_decision.trust_level.unwrap_or(TrustLevel::Unknown),
            validation_result,
            revocation_status,
            trust_decision,
            verified_at: SystemTime::now(),
        };
        
        // Cache the result
        {
            let mut cache = self.cache.write().await;
            cache.insert_verification_result(cert_id, CachedVerificationResult {
                result: verification_result.clone(),
                cached_at: SystemTime::now(),
                ttl: Duration::from_secs(300), // 5 minutes
            });
        }
        
        // Log audit event
        self.audit_logger.log_certificate_verification(&verification_result).await?;
        
        Ok(verification_result)
    }
    
    /// Find certificates by various criteria
    pub async fn find_certificates(
        &self,
        criteria: &CertificateSearchCriteria,
    ) -> Result<Vec<Certificate>, TrustStoreError> {
        match criteria {
            CertificateSearchCriteria::BySubject(subject) => {
                self.storage.find_certificates_by_subject(subject).await
            },
            CertificateSearchCriteria::ByIssuer(issuer) => {
                self.storage.find_certificates_by_issuer(issuer).await
            },
            CertificateSearchCriteria::ByKeyId(key_id) => {
                self.storage.find_certificates_by_key_id(key_id).await
            },
            CertificateSearchCriteria::ByTrustLevel(trust_level) => {
                let filter = CertificateFilter::TrustLevel(*trust_level);
                let cert_ids = self.storage.list_certificates(Some(&filter)).await?;
                
                let mut certificates = Vec::new();
                for cert_id in cert_ids {
                    if let Some(cert) = self.storage.get_certificate(&cert_id).await? {
                        certificates.push(cert);
                    }
                }
                Ok(certificates)
            },
            CertificateSearchCriteria::ByAlgorithm(algorithm) => {
                let filter = CertificateFilter::Algorithm(*algorithm);
                let cert_ids = self.storage.list_certificates(Some(&filter)).await?;
                
                let mut certificates = Vec::new();
                for cert_id in cert_ids {
                    if let Some(cert) = self.storage.get_certificate(&cert_id).await? {
                        certificates.push(cert);
                    }
                }
                Ok(certificates)
            },
        }
    }
    
    /// Update certificate trust level
    pub async fn update_certificate_trust(
        &mut self,
        certificate_id: &CertificateId,
        new_trust_level: TrustLevel,
        reason: TrustUpdateReason,
    ) -> Result<(), TrustStoreError> {
        // Get current trust information
        let current_trust = self.get_certificate_trust(certificate_id).await?;
        
        // Update trust information
        let updated_trust = CertificateTrust {
            certificate_id: certificate_id.clone(),
            trust_level: new_trust_level,
            trust_path: current_trust.trust_path,
            established_at: current_trust.established_at,
            expires_at: current_trust.expires_at,
            establishment_reason: reason.into(),
            constraints: current_trust.constraints,
        };
        
        self.storage.update_certificate_trust(certificate_id, &updated_trust).await?;
        
        // Invalidate cache
        {
            let mut cache = self.cache.write().await;
            cache.invalidate_certificate(certificate_id);
        }
        
        // Log audit event
        self.audit_logger.log_trust_level_change(
            certificate_id,
            current_trust.trust_level,
            new_trust_level,
            reason,
        ).await?;
        
        Ok(())
    }
    
    /// Export trust store data
    pub async fn export_trust_store(
        &self,
        export_config: &TrustStoreExportConfig,
    ) -> Result<TrustStoreExport, TrustStoreError> {
        let mut export = TrustStoreExport::new();
        
        // Export certificates
        if export_config.include_certificates {
            let cert_ids = self.storage.list_certificates(None).await?;
            for cert_id in cert_ids {
                if let Some(certificate) = self.storage.get_certificate(&cert_id).await? {
                    let trust_info = self.get_certificate_trust(&cert_id).await?;
                    export.add_certificate(certificate, trust_info);
                }
            }
        }
        
        // Export trust anchors
        if export_config.include_trust_anchors {
            let trust_anchors = self.list_trust_anchors().await?;
            for anchor in trust_anchors {
                export.add_trust_anchor(anchor);
            }
        }
        
        // Export policies
        if export_config.include_policies {
            export.set_policies(self.trust_policy.policies.clone());
        }
        
        Ok(export)
    }
}
```

This comprehensive trust store documentation establishes Quantum Shield as a robust certificate and key management system with quantum-safe capabilities, comprehensive validation, and flexible trust policies.

