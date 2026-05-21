//! Default/Base Security Provider implementation.

use std::sync::Mutex;
use crate::types::{SspiError, CredHandle, CtxtHandle, SecBuffer, SecurityProvider};

/// Base implementation of SecurityProvider corresponding to CSecurityProvider VTable at 0x37205A38.
pub struct DefaultSecurityProvider {
    pub name: String,
    pub creds: Mutex<CredHandle>,
}

impl DefaultSecurityProvider {
    pub fn new() -> Self {
        Self {
            name: "Default".to_string(),
            creds: Mutex::new(CredHandle { dw_lower: 0x1337, dw_upper: 0x9999 }),
        }
    }
}

impl Default for DefaultSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityProvider for DefaultSecurityProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn initialize(&self) -> Result<(), SspiError> {
        Ok(())
    }

    fn shutdown(&self) -> Result<(), SspiError> {
        Ok(())
    }

    fn acquire_credentials_handle(
        &self,
        _principal: Option<&str>,
        _package: &str,
        _cred_use: u32,
        _auth_data: Option<&[u8]>,
        handle: &mut CredHandle,
    ) -> Result<(), SspiError> {
        *handle = *self.creds.lock().unwrap();
        Ok(())
    }

    fn free_credentials_handle(&self, _handle: &CredHandle) -> Result<(), SspiError> {
        Ok(())
    }

    fn initialize_security_context(
        &self,
        _credential: &CredHandle,
        _context: Option<&CtxtHandle>,
        _target_name: Option<&str>,
        _context_req: u32,
        _target_data_rep: u32,
        _input_buffers: &[SecBuffer],
        _new_context: &mut CtxtHandle,
        _output_buffers: &mut [SecBuffer],
        _context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        Err(SspiError::NotSupported)
    }

    fn accept_security_context(
        &self,
        _credential: &CredHandle,
        _context: Option<&CtxtHandle>,
        _input_buffers: &[SecBuffer],
        _context_req: u32,
        _target_data_rep: u32,
        _new_context: &mut CtxtHandle,
        _output_buffers: &mut [SecBuffer],
        _context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        Err(SspiError::NotSupported)
    }

    fn delete_security_context(&self, _context: &CtxtHandle) -> Result<(), SspiError> {
        Ok(())
    }
}
