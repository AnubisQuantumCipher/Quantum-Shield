use anyhow::Result;
use std::ptr;

/// Secure memory region that is locked in RAM and zeroized on drop
#[allow(dead_code)]
pub struct SecureMemory {
    ptr: *mut u8,
    len: usize,
    locked: bool,
}

#[allow(dead_code)]
impl SecureMemory {
    pub fn new(size: usize) -> Result<Self> {
        let layout = std::alloc::Layout::from_size_align(size, 1)
            .map_err(|_| anyhow::anyhow!("Invalid memory layout"))?;
        
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(anyhow::anyhow!("Failed to allocate secure memory"));
        }
        
        let mut mem = SecureMemory {
            ptr,
            len: size,
            locked: false,
        };
        
        // Try to lock memory (may fail on some systems, but continue anyway)
        mem.lock().ok();
        
        Ok(mem)
    }
    
    pub fn lock(&mut self) -> Result<()> {
        if !self.locked {
            #[cfg(unix)]
            {
                let result = unsafe { libc::mlock(self.ptr as *const libc::c_void, self.len) };
                if result == 0 {
                    self.locked = true;
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Failed to lock memory"))
                }
            }
            #[cfg(not(unix))]
            {
                // On non-Unix systems, we can't lock memory, but that's okay
                Ok(())
            }
        } else {
            Ok(())
        }
    }
    
    pub fn unlock(&mut self) {
        if self.locked {
            #[cfg(unix)]
            {
                unsafe { libc::munlock(self.ptr as *const libc::c_void, self.len) };
            }
            self.locked = false;
        }
    }
    
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for SecureMemory {
    fn drop(&mut self) {
        // Zeroize memory before unlocking and deallocating
        unsafe {
            ptr::write_bytes(self.ptr, 0, self.len);
        }
        
        self.unlock();
        
        let layout = std::alloc::Layout::from_size_align(self.len, 1).unwrap();
        unsafe {
            std::alloc::dealloc(self.ptr, layout);
        }
    }
}

unsafe impl Send for SecureMemory {}
unsafe impl Sync for SecureMemory {}

/// Constant-time comparison function
#[allow(dead_code)]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Secure random number generation (OS-backed)
#[allow(dead_code)]
pub fn secure_random(buf: &mut [u8]) -> Result<()> {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
    Ok(())
}

/// Disable core dumps for the current process
pub fn disable_core_dumps() -> Result<()> {
    #[cfg(unix)]
    {
        use libc::{setrlimit, rlimit, RLIMIT_CORE};
        let rlim = rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let result = unsafe { setrlimit(RLIMIT_CORE, &rlim) };
        if result == 0 {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to disable core dumps"))
        }
    }
    #[cfg(not(unix))]
    {
        // On non-Unix systems, we can't disable core dumps
        Ok(())
    }
}

/// Set restrictive file permissions (0600)
pub fn set_secure_permissions(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        // On non-Unix systems, we can't set Unix permissions
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_readonly(false);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}
