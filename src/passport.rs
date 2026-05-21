//! Passport Security Provider implementation (Passport Ticket Chunking).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use crate::types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider};
use crate::default::DefaultSecurityProvider;

/// Struct tracking the Passport provider context state chunking.
pub struct PassportSession {
    pub h_context: CtxtHandle,
    pub is_finished: bool,
    pub remaining_token: Vec<u8>,
    pub client_info: String,
}

fn is_printable_ascii(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    bytes.iter().all(|&b| b == b'\t' || b == b'\r' || b == b'\n' || (b >= 32 && b <= 126))
}

/// Passport Security Provider corresponding to VTable at 0x37205B70.
/// Manages standard HTTP/HTTPS MSN Passport authentication token chunking.
pub struct PassportSecurityProvider {
    pub base: DefaultSecurityProvider,
    pub sessions: Arc<Mutex<HashMap<CtxtHandle, PassportSession>>>,
    pub next_handle_id: Arc<Mutex<usize>>,
}

impl PassportSecurityProvider {
    pub fn new() -> Self {
        Self {
            base: DefaultSecurityProvider {
                name: "Passport".to_string(),
                creds: Mutex::new(CredHandle { dw_lower: 0x2001, dw_upper: 0x7777 }),
            },
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_handle_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for PassportSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityProvider for PassportSecurityProvider {
    fn name(&self) -> &str {
        self.base.name()
    }

    fn initialize(&self) -> Result<(), SspiError> {
        self.base.initialize()
    }

    fn shutdown(&self) -> Result<(), SspiError> {
        self.base.shutdown()
    }

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

    fn free_credentials_handle(&self, handle: &CredHandle) -> Result<(), SspiError> {
        self.base.free_credentials_handle(handle)
    }

    fn initialize_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        target_name: Option<&str>,
        _context_req: u32,
        target_data_rep: u32,
        input_buffers: &[SecBuffer],
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        _context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        if credential.dw_lower != self.base.creds.lock().unwrap().dw_lower {
            return Err(SspiError::UnknownCredentials);
        }
        if target_name.is_some() {
            return Err(SspiError::TargetUnknown);
        }
        if target_data_rep != 16 {
            return Err(SspiError::NotSupported);
        }

        // Get Passport Ticket/Profile Token from input buffer
        let input_tok = input_buffers.iter()
            .find(|b| b.buffer_type == SecBufferType::Token)
            .ok_or(SspiError::InvalidToken)?;

        // Find output buffer to fill
        let output_tok = output_buffers.iter_mut()
            .find(|b| b.buffer_type == SecBufferType::Token)
            .ok_or(SspiError::InvalidToken)?;

        let mut sessions = self.sessions.lock().unwrap();
        match context {
            None => {
                // Initialize chunking state machine
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x3000 };
                *handle_id += 1;
                *new_context = ctxt;

                let token_len = input_tok.bytes.len();
                if token_len > 4096 {
                    return Err(SspiError::InvalidToken);
                }
                if token_len > 480 {
                    // Split token chunk
                    output_tok.bytes = input_tok.bytes[..480].to_vec();
                    let remaining = input_tok.bytes[480..].to_vec();
                    sessions.insert(ctxt, PassportSession {
                        h_context: ctxt,
                        is_finished: false,
                        remaining_token: remaining,
                        client_info: String::new(),
                    });
                    Ok(SspiError::ContinueNeeded)
                } else {
                    // Send entire token
                    output_tok.bytes = input_tok.bytes.clone();
                    sessions.insert(ctxt, PassportSession {
                        h_context: ctxt,
                        is_finished: true,
                        remaining_token: Vec::new(),
                        client_info: String::new(),
                    });
                    Ok(SspiError::Ok)
                }
            }
            Some(ctxt) => {
                let session = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;
                if session.is_finished {
                    // Finished parsing, finalize by checking ticket client info validation
                    session.client_info = String::from_utf8_lossy(&input_tok.bytes).to_string();
                    Ok(SspiError::Ok)
                } else {
                    // Copy next chunk
                    let remaining_len = session.remaining_token.len();
                    if remaining_len > 480 {
                        output_tok.bytes = session.remaining_token[..480].to_vec();
                        session.remaining_token = session.remaining_token[480..].to_vec();
                        Ok(SspiError::ContinueNeeded)
                    } else {
                        output_tok.bytes = session.remaining_token.clone();
                        session.remaining_token.clear();
                        session.is_finished = true;
                        Ok(SspiError::Ok)
                    }
                }
            }
        }
    }

    fn accept_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        input_buffers: &[SecBuffer],
        _context_req: u32,
        target_data_rep: u32,
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        _context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        if credential.dw_lower != self.base.creds.lock().unwrap().dw_lower {
            return Err(SspiError::UnknownCredentials);
        }
        if target_data_rep != 16 {
            return Err(SspiError::NotSupported);
        }

        // Get Passport Ticket/Profile Token from input buffer
        let input_tok = input_buffers.iter()
            .find(|b| b.buffer_type == SecBufferType::Token)
            .ok_or(SspiError::InvalidToken)?;

        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                // Initialize chunking state machine on server side
                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x3000 };
                *handle_id += 1;
                *new_context = ctxt;

                let chunk_len = input_tok.bytes.len();
                if chunk_len > 480 {
                    return Err(SspiError::InvalidToken);
                }

                if chunk_len == 480 {
                    // Start of multi-chunk sequence
                    let output_tok = output_buffers.iter_mut()
                        .find(|b| b.buffer_type == SecBufferType::Token)
                        .ok_or(SspiError::InvalidToken)?;
                    output_tok.bytes = b"OK".to_vec();

                    sessions.insert(ctxt, PassportSession {
                        h_context: ctxt,
                        is_finished: false,
                        remaining_token: input_tok.bytes.clone(),
                        client_info: String::new(),
                    });
                    Ok(SspiError::ContinueNeeded)
                } else {
                    // Complete ticket in a single chunk
                    let client_info = if is_printable_ascii(&input_tok.bytes) {
                        String::from_utf8_lossy(&input_tok.bytes).to_string()
                    } else {
                        String::new()
                    };
                    sessions.insert(ctxt, PassportSession {
                        h_context: ctxt,
                        is_finished: true,
                        remaining_token: Vec::new(),
                        client_info,
                    });
                    Ok(SspiError::Ok)
                }
            }
            Some(ctxt) => {
                let session = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;
                if session.is_finished {
                    return Err(SspiError::InvalidHandle);
                }

                let chunk_len = input_tok.bytes.len();
                if chunk_len > 480 {
                    return Err(SspiError::InvalidToken);
                }

                // Enforce safety limits: maximum total ticket size of 4096 bytes
                if session.remaining_token.len() + chunk_len > 4096 {
                    return Err(SspiError::InvalidToken);
                }

                session.remaining_token.extend_from_slice(&input_tok.bytes);

                if chunk_len == 480 {
                    // More chunks expected
                    let output_tok = output_buffers.iter_mut()
                        .find(|b| b.buffer_type == SecBufferType::Token)
                        .ok_or(SspiError::InvalidToken)?;
                    output_tok.bytes = b"OK".to_vec();
                    Ok(SspiError::ContinueNeeded)
                } else {
                    // Final chunk received
                    let client_info = if is_printable_ascii(&session.remaining_token) {
                        String::from_utf8_lossy(&session.remaining_token).to_string()
                    } else {
                        String::new()
                    };
                    session.client_info = client_info;
                    session.remaining_token.clear();
                    session.is_finished = true;
                    Ok(SspiError::Ok)
                }
            }
        }
    }

    fn delete_security_context(&self, context: &CtxtHandle) -> Result<(), SspiError> {
        self.sessions.lock().unwrap().remove(context);
        Ok(())
    }
}
