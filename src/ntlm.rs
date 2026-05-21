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
use md4::{Md4, Digest as Md4Digest};
use md5::Md5;
use hmac::{Hmac, Mac};

type HmacMd5 = Hmac<Md5>;

/// Represents an active NTLM session holding its `sspi::Ntlm` state machine
/// and its associated native credentials handle.
pub struct NtlmSession {
    /// The cross-platform NTLM state engine.
    pub ntlm: sspi::Ntlm,
    /// The specific credentials handle bound to this NTLM session.
    pub creds_handle: <sspi::Ntlm as sspi::SspiImpl>::CredentialsHandle,
    /// The 8-byte server challenge generated during server leg 1.
    pub server_challenge: Option<[u8; 8]>,
    /// The TargetName sent by the server in the Type 2 challenge message.
    pub server_target_name: Option<String>,
    /// The authenticated username post-handshake
    pub authenticated_username: Option<String>,
    /// The authenticated user level post-handshake
    pub authenticated_level: Option<crate::vault::UserLevel>,
    /// The authenticated domain post-handshake
    pub authenticated_domain: Option<String>,
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
                    username: sspi::Username::new("TestUser", None).unwrap(),
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
                    server_challenge: None,
                    server_target_name: None,
                    authenticated_username: None,
                    authenticated_level: None,
                    authenticated_domain: None,
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

                // Extract server challenge and target name from output token
                let mut server_challenge = None;
                let mut server_target_name = None;
                if let Some(s_buf) = output_sspi.iter().find(|b| b.buffer_type.buffer_type == sspi::BufferType::Token) {
                    let msg = &s_buf.buffer;
                    if msg.len() >= 32 {
                        let mut challenge = [0u8; 8];
                        challenge.copy_from_slice(&msg[24..32]);
                        server_challenge = Some(challenge);

                        // Parse TargetName from Type 2 message if available
                        if msg.starts_with(b"NTLMSSP\0") && msg.len() >= 20 {
                            if let Ok(desc) = parse_descriptor(msg, 12) {
                                if desc.offset + desc.length <= msg.len() {
                                    let target_name = decode_utf16le(&msg[desc.offset .. desc.offset + desc.length]);
                                    server_target_name = Some(target_name);
                                }
                            }
                        }
                    }
                }

                // Save active NTLM server session state
                sessions.insert(ctxt, NtlmSession {
                    ntlm,
                    creds_handle: acq_res.credentials_handle,
                    server_challenge,
                    server_target_name,
                    authenticated_username: None,
                    authenticated_level: None,
                    authenticated_domain: None,
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

                // Parse and verify client Type 3 credentials cryptographically
                let token_buf = input_buffers
                    .iter()
                    .find(|b| b.buffer_type == SecBufferType::Token)
                    .ok_or(SspiError::InvalidToken)?;
                let type3_msg = &token_buf.bytes;

                if type3_msg.len() < 64 || !type3_msg.starts_with(b"NTLMSSP\0") || type3_msg[8..12] != [3, 0, 0, 0] {
                    return Err(SspiError::InvalidToken);
                }

                let nt_desc = parse_descriptor(type3_msg, 20)?;
                let domain_desc = parse_descriptor(type3_msg, 28)?;
                let user_desc = parse_descriptor(type3_msg, 36)?;

                let domain = decode_utf16le(&type3_msg[domain_desc.offset .. domain_desc.offset + domain_desc.length]);
                let username = decode_utf16le(&type3_msg[user_desc.offset .. user_desc.offset + user_desc.length]);
                let nt_resp = &type3_msg[nt_desc.offset .. nt_desc.offset + nt_desc.length];

                if nt_resp.len() < 16 {
                    return Err(SspiError::InvalidToken);
                }

                let client_proof = &nt_resp[0..16];
                let temp_blob = &nt_resp[16..];

                let server_challenge = session.server_challenge.ok_or(SspiError::LogonDenied)?;

                 let key = match crate::vault::load_master_key() {
                    Ok(k) => k,
                    Err(e) => {
                        println!("ERROR: failed to load master key: {:?}", e);
                        return Err(SspiError::LogonDenied);
                    }
                };
                let map = match crate::vault::load_and_decrypt_vault(&key) {
                    Ok(m) => m,
                    Err(e) => {
                        println!("ERROR: failed to load/decrypt vault: {:?}", e);
                        return Err(SspiError::LogonDenied);
                    }
                };
                let account = match map.get(&username.to_lowercase()) {
                    Some(a) => a,
                    None => {
                        println!("ERROR: username not found in vault: '{}'. Loaded keys: {:?}", username, map.keys().collect::<Vec<_>>());
                        return Err(SspiError::LogonDenied);
                    }
                };

                // Enforce domain validation and build candidate list for proof verification.
                // - No domain in vault: accept only "" and "." from the client.
                // - Domain in vault: require case-insensitive match against the stored domain.
                let client_domain_trimmed = domain.trim();
                let mut candidate_domains = Vec::new();

                if account.domain.is_empty() {
                    // No domain stored: only "" and "." are valid
                    if !client_domain_trimmed.is_empty() && client_domain_trimmed != "." {
                        println!("ERROR: Domain mismatch: client='{}', db='' (expected empty or '.')", domain);
                        return Err(SspiError::LogonDenied);
                    }
                    candidate_domains.push("".to_string());
                    candidate_domains.push(".".to_string());
                } else {
                    // Domain stored: case-insensitive match required
                    if !client_domain_trimmed.eq_ignore_ascii_case(account.domain.trim()) {
                        println!("ERROR: Domain mismatch: client='{}', db='{}'", domain, account.domain);
                        return Err(SspiError::LogonDenied);
                    }
                    // Use the client-provided casing (what the client used to compute their proof)
                    candidate_domains.push(domain.clone());
                }

                let mut nt_hash = [0u8; 16];
                if hex::decode_to_slice(&account.nt_hash, &mut nt_hash).is_err() {
                    println!("ERROR: failed to hex decode NT hash");
                    return Err(SspiError::LogonDenied);
                }

                // Ephemerally hold decrypted hash in zeroizing container
                let sam_package = crate::internal::sam::SamPackage::new(username.clone(), nt_hash);

                let mut is_valid = false;

                for candidate in &candidate_domains {
                    let ntlmv2_hash = calculate_ntlmv2_hash(&sam_package.username, candidate, &sam_package.nt_hash);
                    let proof = calculate_ntlmv2_proof(&ntlmv2_hash, &server_challenge, temp_blob);
                    if client_proof == proof {
                        is_valid = true;
                        break;
                    }
                }

                if !is_valid {
                    // Try to print the client-supplied domain proof expectation for error diagnostics
                    let ntlmv2_hash = calculate_ntlmv2_hash(&sam_package.username, &domain, &sam_package.nt_hash);
                    let expected_proof = calculate_ntlmv2_proof(&ntlmv2_hash, &server_challenge, temp_blob);
                    println!("ERROR: Client proof mismatch! expected={:?}, got={:?}", expected_proof, client_proof);
                }

                // Explicitly drop/zeroize plain credentials post-handshake
                drop(sam_package);

                if !is_valid {
                    return Err(SspiError::LogonDenied);
                }

                session.authenticated_username = Some(account.username.clone());
                session.authenticated_level = Some(account.level);
                session.authenticated_domain = Some(account.domain.clone());

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

// --- Cryptographic Helper Functions for NetNTLMv2 Authentication Verification ---

pub fn to_utf16le(s: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for c in s.encode_utf16() {
        bytes.extend_from_slice(&c.to_le_bytes());
    }
    bytes
}

pub fn calculate_nt_hash(password: &str) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(&to_utf16le(password));
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&hasher.finalize());
    hash
}

pub fn calculate_ntlmv2_hash(username: &str, domain: &str, nt_hash: &[u8; 16]) -> [u8; 16] {
    let upper_user = username.to_uppercase();
    // Per MS-NLMP spec: HMAC_MD5(NT_Hash, UNICODE(Uppercase(Username) + UserDomain))
    // Only the username is uppercased; the domain is used as-is.
    let mut identity = to_utf16le(&upper_user);
    identity.extend_from_slice(&to_utf16le(domain));

    let mut mac = HmacMd5::new_from_slice(nt_hash).unwrap();
    mac.update(&identity);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&mac.finalize().into_bytes());
    hash
}

pub fn calculate_ntlmv2_proof(
    ntlmv2_hash: &[u8; 16],
    server_challenge: &[u8; 8],
    temp_blob: &[u8],
) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(ntlmv2_hash).unwrap();
    mac.update(server_challenge);
    mac.update(temp_blob);
    let mut proof = [0u8; 16];
    proof.copy_from_slice(&mac.finalize().into_bytes());
    proof
}

struct SecurityBufferDescriptor {
    length: usize,
    offset: usize,
}

fn parse_descriptor(msg: &[u8], offset: usize) -> Result<SecurityBufferDescriptor, SspiError> {
    if offset + 8 > msg.len() {
        return Err(SspiError::InvalidToken);
    }
    let length = u16::from_le_bytes([msg[offset], msg[offset + 1]]) as usize;
    let msg_offset = u32::from_le_bytes([
        msg[offset + 4],
        msg[offset + 5],
        msg[offset + 6],
        msg[offset + 7],
    ]) as usize;

    if msg_offset + length > msg.len() {
        return Err(SspiError::InvalidToken);
    }

    Ok(SecurityBufferDescriptor {
        length,
        offset: msg_offset,
    })
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let u16s: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}
