use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SuiteId {
    Aes256Gcm = 1,
    Aes256GcmSiv = 2,
}

impl SuiteId {
    pub fn current() -> Self {
        #[cfg(feature = "gcm-siv")]
        { SuiteId::Aes256GcmSiv }
        #[cfg(all(not(feature = "gcm-siv"), feature = "gcm"))]
        { SuiteId::Aes256Gcm }
        #[cfg(all(not(feature = "gcm-siv"), not(feature = "gcm")))]
        { SuiteId::Aes256GcmSiv } // Default fallback
    }
    pub fn as_bytes(self) -> [u8; 1] { [self as u8] }
    pub fn as_str(self) -> &'static str {
        match self {
            SuiteId::Aes256Gcm => "aes256-gcm",
            SuiteId::Aes256GcmSiv => "aes256-gcm-siv",
        }
    }
}

