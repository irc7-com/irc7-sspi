//! # MSN Chat NTLM Security Provider
//!
//! Provides the core implementation of the NTLM Security Support Provider (SSP),
//! matching the original C++ virtual table at `0x372042D8` in the MSN Chat Control.
//!
//! This implementation utilizes the cross-platform `sspi-rs` library to provide
//! authentic NTLM client and server handshakes, making it fully operational on
//! Windows, Linux, and macOS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use sspi::{Sspi, SspiImpl};
use crate::types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider};
use crate::default::DefaultSecurityProvider;

/// Represents an active NTLM session holding its `sspi::Ntlm` state machine
/// and its associated native credentials handle.
pub struct NtlmSession {
    /// The cross-platform NTLM state engine.
    pub ntlm: sspi::Ntlm,
    /// The specific credentials handle bound to this NTLM session.
    pub creds_handle: <sspi::Ntlm as sspi::SspiImpl>::CredentialsHandle,
}

/// NTLM Security Provider corresponding to MSN Chat's VTable at `0x372042D8`.
/// Manages sessions for both client-side and server-side NTLM negotiations.
pub struct NtlmSecurityProvider {
    /// Base provider containing default properties like the provider name and default handles.
    pub base: DefaultSecurityProvider,
    /// Active sessions map indexing NtlmSession structures by their unique context handle.
    pub sessions: Arc<Mutex<HashMap<CtxtHandle, NtlmSession>>>,
    /// Incremental counter generating unique values for CtxtHandle allocations.
    pub next_handle_id: Arc<Mutex<usize>>,
}

impl NtlmSecurityProvider {
    /// Allocates a new NTLM Security Provider instance.
    pub fn new() -> Self {
        Self {
            base: DefaultSecurityProvider {
                name: "NTLM".to_string(),
                creds: Mutex::new(CredHandle { dw_lower: 0x4001, dw_upper: 0x6666 }),
            },
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_handle_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for NtlmSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper converting a slice of library-native `SecBuffer`s to `sspi`'s `SecurityBuffer`s.
fn to_sspi_buffers(buffers: &[SecBuffer]) -> Vec<sspi::SecurityBuffer> {
    buffers
        .iter()
        .map(|b| {
            let bt = match b.buffer_type {
                SecBufferType::Token => sspi::BufferType::Token,
                _ => sspi::BufferType::Token,
            };
            sspi::SecurityBuffer::new(b.bytes.clone(), bt)
        })
        .collect()
}

/// Helper extracting NTLM token outputs from `sspi` buffers and writing them back
/// to the caller's target `SecBuffer` slice.
fn from_sspi_buffers(sspi_buffers: &[sspi::SecurityBuffer], output_buffers: &mut [SecBuffer]) {
    for s_buf in sspi_buffers {
        if s_buf.buffer_type.buffer_type == sspi::BufferType::Token {
            if let Some(out_buf) = output_buffers.iter_mut().find(|b| b.buffer_type == SecBufferType::Token) {
                out_buf.bytes = s_buf.buffer.clone();
            }
        }
    }
}

impl SecurityProvider for NtlmSecurityProvider {
    /// Returns the standard package name: "NTLM".
    fn name(&self) -> &str {
        self.base.name()
    }

    /// Initializes global resources for the NTLM security provider.
    fn initialize(&self) -> Result<(), SspiError> {
        self.base.initialize()
    }

    /// Deinitializes global resources for the NTLM security provider.
    fn shutdown(&self) -> Result<(), SspiError> {
        self.base.shutdown()
    }

    /// Acquires a handle to pre-existing credentials for NTLM.
    fn acquire_credentials_handle(
        &self,
        principal: Option<&str>,
        package: &str,
        cred_use: u32,
        auth_data: Option<&[u8]>,
        handle: &mut CredHandle,
    ) -> Result<(), SspiError> {
        self.base.acquire_credentials_handle(principal, package, cred_use, auth_data, handle)
    }

    /// Frees acquired credentials handle.
    fn free_credentials_handle(&self, handle: &CredHandle) -> Result<(), SspiError> {
        self.base.free_credentials_handle(handle)
    }

    /// Client-side Security Context Initialization.
    /// Drives NTLM negotiation (Type 1 Negotiate -> Type 3 Authenticate).
    fn initialize_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        _target_name: Option<&str>,
        _context_req: u32,
        _target_data_rep: u32,
        input_buffers: &[SecBuffer],
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        _context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        // Validate credentials handle matching self.base.creds
        if credential.dw_lower != self.base.creds.lock().unwrap().dw_lower {
            return Err(SspiError::UnknownCredentials);
        }

        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                // Client Step 1: Initialize new NTLM instance and negotiate Type 1 message
                let mut ntlm = sspi::Ntlm::new();

                // Setup fallback credentials for cross-platform NTLM authentication
                let identity = sspi::AuthIdentity {
                    username: sspi::Username::new("user", None).unwrap(),
                    password: "password".to_string().into(),
                };

                // Acquire client-side credentials handle
                let mut acq_res = ntlm.acquire_credentials_handle()
                    .with_credential_use(sspi::CredentialUse::Outbound)
                    .with_auth_data(&identity)
                    .execute(&mut ntlm)
                    .map_err(|_| SspiError::UnknownCredentials)?;

                let mut output_sspi = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];

                // Run client step 1 and extract the negotiate token
                let res = {
                    let mut builder = ntlm.initialize_security_context()
                        .with_credentials_handle(&mut acq_res.credentials_handle)
                        .with_context_requirements(sspi::ClientRequestFlags::empty())
                        .with_target_data_representation(sspi::DataRepresentation::Native)
                        .with_output(&mut output_sspi);

                    let mut generator = ntlm.initialize_security_context_impl(&mut builder)
                        .map_err(|_| SspiError::InvalidToken)?;
                    generator.resolve_to_result().map_err(|_| SspiError::InvalidToken)?
                };

                // Copy output token bytes back to caller buffers
                from_sspi_buffers(&output_sspi, output_buffers);

                // Allocate a new unique context handle
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x5000 };
                *handle_id += 1;
                *new_context = ctxt;

                // Save active NTLM session state
                sessions.insert(ctxt, NtlmSession {
                    ntlm,
                    creds_handle: acq_res.credentials_handle,
                });

                // Return mapped status
                match res.status {
                    sspi::SecurityStatus::Ok => Ok(SspiError::Ok),
                    sspi::SecurityStatus::ContinueNeeded => Ok(SspiError::ContinueNeeded),
                    sspi::SecurityStatus::CompleteNeeded => Ok(SspiError::Ok),
                    _ => Err(SspiError::InvalidToken),
                }
            }
            Some(ctxt) => {
                // Client Step 2: Receive server's Type 2 challenge and respond with Type 3 authentications
                let session = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;

                let mut input_sspi = to_sspi_buffers(input_buffers);
                let mut output_sspi = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];

                // Run client step 2
                let res = {
                    let mut builder = session.ntlm.initialize_security_context()
                        .with_credentials_handle(&mut session.creds_handle)
                        .with_context_requirements(sspi::ClientRequestFlags::empty())
                        .with_target_data_representation(sspi::DataRepresentation::Native)
                        .with_input(&mut input_sspi)
                        .with_output(&mut output_sspi);

                    let mut generator = session.ntlm.initialize_security_context_impl(&mut builder)
                        .map_err(|_| SspiError::InvalidToken)?;
                    generator.resolve_to_result().map_err(|_| SspiError::InvalidToken)?
                };

                // Copy outputs
                from_sspi_buffers(&output_sspi, output_buffers);

                // Return mapped status
                match res.status {
                    sspi::SecurityStatus::Ok => Ok(SspiError::Ok),
                    sspi::SecurityStatus::ContinueNeeded => Ok(SspiError::ContinueNeeded),
                    sspi::SecurityStatus::CompleteNeeded => Ok(SspiError::Ok),
                    _ => Err(SspiError::InvalidToken),
                }
            }
        }
    }

    /// Server-side Security Context Acceptance.
    /// establishment steps (Processes Type 1 -> Generates Type 2 Challenge -> Validates Type 3).
    fn accept_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        input_buffers: &[SecBuffer],
        _context_req: u32,
        _target_data_rep: u32,
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        _context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        // Validate credentials handle
        if credential.dw_lower != self.base.creds.lock().unwrap().dw_lower {
            return Err(SspiError::UnknownCredentials);
        }

        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                // Server Step 1: Receive client negotiate message and produce server challenge
                let mut ntlm = sspi::Ntlm::new();

                // Acquire server-side credentials handle
                let mut acq_res = ntlm.acquire_credentials_handle()
                    .with_credential_use(sspi::CredentialUse::Inbound)
                    .execute(&mut ntlm)
                    .map_err(|_| SspiError::UnknownCredentials)?;

                let mut input_sspi = to_sspi_buffers(input_buffers);
                let mut output_sspi = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];

                // Run server step 1
                let res = {
                    let builder = ntlm.accept_security_context()
                        .with_credentials_handle(&mut acq_res.credentials_handle)
                        .with_context_requirements(sspi::ServerRequestFlags::empty())
                        .with_target_data_representation(sspi::DataRepresentation::Native)
                        .with_input(&mut input_sspi)
                        .with_output(&mut output_sspi);

                    ntlm.accept_security_context_impl(builder)
                        .map_err(|_| SspiError::InvalidToken)?
                        .resolve_to_result()
                        .map_err(|_| SspiError::InvalidToken)?
                };

                // Copy challenge token back to caller buffers
                from_sspi_buffers(&output_sspi, output_buffers);

                // Allocate server-side context handle
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x6000 };
                *handle_id += 1;
                *new_context = ctxt;

                // Save active NTLM server session state
                sessions.insert(ctxt, NtlmSession {
                    ntlm,
                    creds_handle: acq_res.credentials_handle,
                });

                // Return mapped status
                match res.status {
                    sspi::SecurityStatus::Ok => Ok(SspiError::Ok),
                    sspi::SecurityStatus::ContinueNeeded => Ok(SspiError::ContinueNeeded),
                    sspi::SecurityStatus::CompleteNeeded => Ok(SspiError::Ok),
                    _ => Err(SspiError::InvalidToken),
                }
            }
            Some(ctxt) => {
                // Server Step 2: Validate the client's Type 3 authentication message
                let session = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;

                let mut input_sspi = to_sspi_buffers(input_buffers);
                let mut output_sspi = vec![sspi::SecurityBuffer::new(Vec::new(), sspi::BufferType::Token)];

                // Run server step 2
                let res = {
                    let builder = session.ntlm.accept_security_context()
                        .with_credentials_handle(&mut session.creds_handle)
                        .with_context_requirements(sspi::ServerRequestFlags::empty())
                        .with_target_data_representation(sspi::DataRepresentation::Native)
                        .with_input(&mut input_sspi)
                        .with_output(&mut output_sspi);

                    session.ntlm.accept_security_context_impl(builder)
                        .map_err(|_| SspiError::InvalidToken)?
                        .resolve_to_result()
                        .map_err(|_| SspiError::InvalidToken)?
                };

                // Copy output tokens
                from_sspi_buffers(&output_sspi, output_buffers);

                // Return mapped status
                match res.status {
                    sspi::SecurityStatus::Ok => Ok(SspiError::Ok),
                    sspi::SecurityStatus::ContinueNeeded => Ok(SspiError::ContinueNeeded),
                    sspi::SecurityStatus::CompleteNeeded => Ok(SspiError::Ok),
                    _ => Err(SspiError::InvalidToken),
                }
            }
        }
    }

    /// Deletes and cleans up an NTLM security context.
    fn delete_security_context(&self, context: &CtxtHandle) -> Result<(), SspiError> {
        self.sessions.lock().unwrap().remove(context);
        Ok(())
    }
}
