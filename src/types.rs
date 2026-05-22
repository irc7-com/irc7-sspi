//! Core SSPI traits, enums, handles, and shared types.

/// Standard Windows SSPI Status Codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SspiError {
    /// The function completed successfully.
    Ok = 0,
    /// The function completed successfully, but the caller must call again to complete.
    ContinueNeeded = 0x00090312,
    /// The credentials handle supplied is not valid.
    UnknownCredentials = -2146893043,
    /// The context handle supplied is not valid.
    InvalidHandle = -2146893055,
    /// The target name is not recognized or not reachable.
    TargetUnknown = -2146893053,
    /// The function or security package is not supported.
    NotSupported = -2146893054,
    /// The buffer passed to the function was invalid or too small.
    InvalidToken = -2146893048,
    /// The logon attempt failed or credentials were rejected.
    LogonDenied = -2146893044,
}

impl SspiError {
    /// Helper to convert the code to a raw i32.
    pub fn to_raw(self) -> i32 {
        self as i32
    }
}

/// A standard Credential Handle mapping to MS SSPI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CredHandle {
    pub dw_lower: usize,
    pub dw_upper: usize,
}

/// A standard Security Context Handle mapping to MS SSPI.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CtxtHandle {
    pub dw_lower: usize,
    pub dw_upper: usize,
}

/// Represents the type of buffer in SecBufferDesc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecBufferType {
    /// Token data generated/exchanged.
    Token = 2,
    /// Package-specific parameters (e.g., hostname, keys).
    PkgParams = 3,
    /// Unused/Unknown buffer type.
    Other,
}

impl From<u32> for SecBufferType {
    fn from(val: u32) -> Self {
        match val {
            2 => SecBufferType::Token,
            3 => SecBufferType::PkgParams,
            _ => SecBufferType::Other,
        }
    }
}

/// Represents a single SSPI SecBuffer containing raw bytes.
#[derive(Debug, Clone)]
pub struct SecBuffer {
    pub buffer_type: SecBufferType,
    pub bytes: Vec<u8>,
}

/// Security Support Provider Interface (SSPI) base trait.
/// Maps directly to the virtual tables located in the original C++ MSN Chat Control.
pub trait SecurityProvider: Send + Sync {
    /// Retrieves the name of the security provider.
    fn name(&self) -> &str;

    /// Initializes the provider.
    fn initialize(&self) -> Result<(), SspiError>;

    /// Shuts down the provider.
    fn shutdown(&self) -> Result<(), SspiError>;

    /// Acquires a handle to pre-existing credentials.
    fn acquire_credentials_handle(
        &self,
        principal: Option<&str>,
        package: &str,
        cred_use: u32,
        auth_data: Option<&[u8]>,
        handle: &mut CredHandle,
    ) -> Result<(), SspiError>;

    /// Frees the credential handle.
    fn free_credentials_handle(&self, handle: &CredHandle) -> Result<(), SspiError>;

    /// Client-side Security Context Initialization.
    #[allow(clippy::too_many_arguments)]
    fn initialize_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        target_name: Option<&str>,
        context_req: u32,
        target_data_rep: u32,
        input_buffers: &[SecBuffer],
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        context_attr: &mut u32,
    ) -> Result<SspiError, SspiError>;

    /// Server-side Security Context Acceptance.
    #[allow(clippy::too_many_arguments)]
    fn accept_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        input_buffers: &[SecBuffer],
        context_req: u32,
        target_data_rep: u32,
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        context_attr: &mut u32,
    ) -> Result<SspiError, SspiError>;

    /// Deletes a security context.
    fn delete_security_context(&self, context: &CtxtHandle) -> Result<(), SspiError>;
}

