//! GateKeeper Security Provider implementation (GKSSP).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use hmac::{Hmac, Mac};
use md5::Md5;
use crate::types::{SspiError, CredHandle, CtxtHandle, SecBufferType, SecBuffer, SecurityProvider};
use crate::default::DefaultSecurityProvider;

/// State flags for active GateKeeper sessions.
#[derive(Debug, Clone, Copy, Default)]
pub struct GkStateFlags {
    pub is_validated_input: bool,
    pub is_init_output: bool,
    pub is_step2_ready: bool,
    pub is_step2_hmac_done: bool,
}

/// Struct tracking details for active GateKeeper Session States.
pub struct GateKeeperSession {
    pub h_context: CtxtHandle,
    pub flags: GkStateFlags,
    pub challenge: [u8; 8],
    pub hostname: String,
    pub hmac_response: [u8; 16],
    pub gatekeeper_id: [u8; 16],
    /// Shared key originally decrypted from the control binary.
    pub gk_shared_key: [u8; 16],
    /// Compatibility mode flag (from pkg_params index 1)
    pub allow_older_versions: bool,
}

impl GateKeeperSession {
    pub fn new(h_context: CtxtHandle) -> Self {
        // Original decrypted key: "SRFMKSJANDRESKKC" (16 bytes)
        let key_bytes = b"SRFMKSJANDRESKKC";
        let mut gk_shared_key = [0u8; 16];
        gk_shared_key.copy_from_slice(key_bytes);

        Self {
            h_context,
            flags: GkStateFlags::default(),
            challenge: [0u8; 8],
            hostname: String::new(),
            hmac_response: [0u8; 16],
            gatekeeper_id: [0u8; 16],
            gk_shared_key,
            allow_older_versions: false,
        }
    }
}

/// GateKeeper Security Provider corresponding to VTable at 0x37204218.
/// Re-creates custom challenge-response SSPI authentication mechanism for MSN Chat.
pub struct GateKeeperSecurityProvider {
    pub base: DefaultSecurityProvider,
    pub sessions: Arc<Mutex<HashMap<CtxtHandle, GateKeeperSession>>>,
    pub next_handle_id: Arc<Mutex<usize>>,
}

impl GateKeeperSecurityProvider {
    pub fn new() -> Self {
        Self {
            base: DefaultSecurityProvider {
                name: "GateKeeper".to_string(),
                creds: Mutex::new(CredHandle { dw_lower: 0x3001, dw_upper: 0x8888 }),
            },
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_handle_id: Arc::new(Mutex::new(1)),
        }
    }
}

impl Default for GateKeeperSecurityProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityProvider for GateKeeperSecurityProvider {
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

        let output_tok = output_buffers.iter_mut()
            .find(|b| b.buffer_type == SecBufferType::Token)
            .ok_or(SspiError::InvalidToken)?;

        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                // GKSSP Step 1 (Client): Create session and generate initialization token
                let gk_id_buf = input_buffers.iter()
                    .find(|b| b.buffer_type == SecBufferType::PkgParams && b.bytes.len() == 16)
                    .ok_or(SspiError::InvalidToken)?;

                // Find hostname buffer: ignore any 4-byte buffer that represents client version override
                let hostname_buf = input_buffers.iter()
                    .find(|b| b.buffer_type == SecBufferType::PkgParams && b.bytes.len() < 16 && b.bytes.len() != 4)
                    .ok_or(SspiError::InvalidToken)?;

                let client_version = if let Some(v_buf) = input_buffers.iter()
                    .find(|b| b.buffer_type == SecBufferType::PkgParams && b.bytes.len() == 4) {
                    u32::from_le_bytes(v_buf.bytes[0..4].try_into().unwrap_or([3, 0, 0, 0]))
                } else {
                    3u32
                };

                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x1000 };
                *handle_id += 1;
                *new_context = ctxt;

                let mut session = GateKeeperSession::new(ctxt);
                session.gatekeeper_id.copy_from_slice(&gk_id_buf.bytes);
                session.hostname = String::from_utf8_lossy(&hostname_buf.bytes).to_string();
                session.flags.is_init_output = true;

                // Build Step 1 Client Token: "GKSSP\0\0\0" (8 bytes) + version (DWORD = client_version) + step (DWORD = 1) -> 16 bytes
                let mut token_bytes = vec![0u8; 16];
                token_bytes[0..6].copy_from_slice(b"GKSSP\0");
                token_bytes[8..12].copy_from_slice(&client_version.to_le_bytes());
                token_bytes[12..16].copy_from_slice(&1u32.to_le_bytes());

                output_tok.bytes = token_bytes;
                sessions.insert(ctxt, session);

                Ok(SspiError::ContinueNeeded)
            }
            Some(ctxt) => {
                // GKSSP Step 2 (Client): Process challenge and calculate HMAC response
                let session = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;
                let input_tok = input_buffers.iter()
                    .find(|b| b.buffer_type == SecBufferType::Token)
                    .ok_or(SspiError::InvalidToken)?;

                // Verify Server Step 2 Token: Size must be exactly 24 bytes, start with "GKSSP\0"
                if input_tok.bytes.len() != 24 || &input_tok.bytes[0..6] != b"GKSSP\0" {
                    return Err(SspiError::InvalidToken);
                }

                let version = u32::from_le_bytes(input_tok.bytes[8..12].try_into().unwrap());
                let step = u32::from_le_bytes(input_tok.bytes[12..16].try_into().unwrap());

                if (version < 1 || version > 4) || step != 2 {
                    return Err(SspiError::InvalidToken);
                }

                // Copy 8-byte challenge
                session.challenge.copy_from_slice(&input_tok.bytes[16..24]);
                session.flags.is_step2_ready = true;

                // Perform HMAC-MD5 calculation over [Challenge (8 bytes)] (+ [Hostname (bytes)] only if version >= 3)
                let mut hmac_payload = Vec::new();
                hmac_payload.extend_from_slice(&session.challenge);
                
                if version >= 3 {
                    let mut host_bytes = session.hostname.as_bytes().to_vec();
                    if host_bytes.len() > 15 {
                        host_bytes.truncate(15);
                    }
                    hmac_payload.extend_from_slice(&host_bytes);
                }

                type HmacMd5 = Hmac<Md5>;
                let mut mac = HmacMd5::new_from_slice(&session.gk_shared_key)
                    .map_err(|_| SspiError::InvalidToken)?;
                mac.update(&hmac_payload);
                let result = mac.finalize().into_bytes();
                session.hmac_response.copy_from_slice(&result);
                session.flags.is_step2_hmac_done = true;

                // Build Step 2 Client Token:
                // - If version is 1: Total size 32 bytes, no GateKeeper ID is sent
                // - If version is 2, 3, or 4: Total size 48 bytes, including 16-byte GateKeeper ID
                let client_response = if version == 1 {
                    let mut response = vec![0u8; 32];
                    response[0..6].copy_from_slice(b"GKSSP\0");
                    response[8..12].copy_from_slice(&version.to_le_bytes());
                    response[12..16].copy_from_slice(&3u32.to_le_bytes());
                    response[16..32].copy_from_slice(&session.hmac_response);
                    response
                } else {
                    let mut response = vec![0u8; 48];
                    response[0..6].copy_from_slice(b"GKSSP\0");
                    response[8..12].copy_from_slice(&version.to_le_bytes());
                    response[12..16].copy_from_slice(&3u32.to_le_bytes());
                    response[16..32].copy_from_slice(&session.hmac_response);
                    response[32..48].copy_from_slice(&session.gatekeeper_id);
                    response
                };

                output_tok.bytes = client_response;

                Ok(SspiError::Ok)
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

        let input_tok = input_buffers.iter()
            .find(|b| b.buffer_type == SecBufferType::Token)
            .ok_or(SspiError::InvalidToken)?;

        let output_tok = output_buffers.iter_mut()
            .find(|b| b.buffer_type == SecBufferType::Token)
            .ok_or(SspiError::InvalidToken)?;

        let mut sessions = self.sessions.lock().unwrap();

        match context {
            None => {
                // GKSSP Step 1 (Server): Validate client initialization, generate challenge
                if input_tok.bytes.len() < 16 || &input_tok.bytes[0..6] != b"GKSSP\0" {
                    return Err(SspiError::InvalidToken);
                }

                let version = u32::from_le_bytes(input_tok.bytes[8..12].try_into().unwrap());
                let step = u32::from_le_bytes(input_tok.bytes[12..16].try_into().unwrap());

                // Extracted parameters
                let pkg_params: Vec<&SecBuffer> = input_buffers.iter()
                    .filter(|b| b.buffer_type == SecBufferType::PkgParams)
                    .collect();

                if pkg_params.is_empty() {
                    return Err(SspiError::InvalidToken);
                }

                let hostname_buf = pkg_params[0];
                let hostname = String::from_utf8_lossy(&hostname_buf.bytes).to_string();

                // PkgParams index 1 holds the allow_older_versions compatibility flag (from ActiveX control)
                let allow_older_versions = if pkg_params.len() > 1 {
                    !pkg_params[1].bytes.is_empty() && pkg_params[1].bytes[0] != 0
                } else {
                    false
                };

                let is_version_ok = if allow_older_versions {
                    version >= 1 && version <= 4
                } else {
                    version >= 3
                };

                if !is_version_ok || step != 1 {
                    return Err(SspiError::InvalidToken);
                }

                let mut handle_id = self.next_handle_id.lock().unwrap();
                let ctxt = CtxtHandle { dw_lower: *handle_id, dw_upper: 0x2000 };
                *handle_id += 1;
                *new_context = ctxt;

                let mut session = GateKeeperSession::new(ctxt);
                session.hostname = hostname;
                session.allow_older_versions = allow_older_versions;
                session.flags.is_validated_input = true;

                // Server generates random 8-byte challenge
                // Simulating rand generator `sub_372407F4() % 255 + 1`
                for i in 0..8 {
                    session.challenge[i] = ((i * 37 + 101) % 254 + 1) as u8;
                }

                // Build Step 1 Server Response Token:
                // - "GKSSP\0\0\0" (8 bytes)
                // - version (DWORD = client's negotiated version)
                // - step (DWORD = 2)
                // - challenge (8 bytes)
                // Total size: 24
                let mut server_tok = vec![0u8; 24];
                server_tok[0..6].copy_from_slice(b"GKSSP\0");
                server_tok[8..12].copy_from_slice(&version.to_le_bytes());
                server_tok[12..16].copy_from_slice(&2u32.to_le_bytes());
                server_tok[16..24].copy_from_slice(&session.challenge);

                output_tok.bytes = server_tok;
                sessions.insert(ctxt, session);

                Ok(SspiError::ContinueNeeded)
            }
            Some(ctxt) => {
                // GKSSP Step 2 (Server): Validate client HMAC-MD5 response and extract GK token ID
                let session = sessions.get_mut(ctxt).ok_or(SspiError::InvalidHandle)?;

                let token_len = input_tok.bytes.len();
                if (token_len != 32 && token_len != 48) || &input_tok.bytes[0..6] != b"GKSSP\0" {
                    return Err(SspiError::InvalidToken);
                }

                let version = u32::from_le_bytes(input_tok.bytes[8..12].try_into().unwrap());
                let step = u32::from_le_bytes(input_tok.bytes[12..16].try_into().unwrap());

                let is_version_ok = if session.allow_older_versions {
                    version >= 1 && version <= 4
                } else {
                    version >= 3
                };

                if !is_version_ok || step != 3 {
                    return Err(SspiError::InvalidToken);
                }

                if version == 1 && token_len != 32 {
                    return Err(SspiError::InvalidToken);
                }
                if version > 1 && token_len != 48 {
                    return Err(SspiError::InvalidToken);
                }

                // Calculate expected HMAC response on server
                // HMAC is computed on challenge (+ hostname only if version >= 3)
                let mut hmac_payload = Vec::new();
                hmac_payload.extend_from_slice(&session.challenge);

                if version >= 3 {
                    let mut host_bytes = session.hostname.as_bytes().to_vec();
                    if host_bytes.len() > 15 {
                        host_bytes.truncate(15);
                    }
                    hmac_payload.extend_from_slice(&host_bytes);
                }

                type HmacMd5 = Hmac<Md5>;
                let mut mac = HmacMd5::new_from_slice(&session.gk_shared_key)
                    .map_err(|_| SspiError::InvalidToken)?;
                mac.update(&hmac_payload);
                let expected_hmac = mac.finalize().into_bytes();

                // Compare client HMAC response
                let client_hmac = &input_tok.bytes[16..32];

                if version >= 3 {
                    let expected_hex: String = expected_hmac.iter().map(|b| format!("{:02x}", b)).collect();
                    let received_hex: String = client_hmac.iter().map(|b| format!("{:02x}", b)).collect();
                    println!("--- GateKeeper v{} Auth Verification ---", version);
                    println!("Hostname:      {:?}", session.hostname);
                    print!("HMAC Input:    ");
                    for byte in &hmac_payload {
                        print!("{:02x} ", byte);
                    }
                    println!();
                    println!("Expected HMAC: {}", expected_hex);
                    println!("Received HMAC: {}", received_hex);
                    println!("----------------------------------------");
                }

                if client_hmac != expected_hmac.as_slice() {
                    return Err(SspiError::LogonDenied);
                }

                // Extract client GateKeeper ID/token
                if version == 1 {
                    let mut seed = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(42) as u64;
                    let mut gk_id = [0u8; 16];
                    for i in 0..16 {
                        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                        gk_id[i] = (seed >> 32) as u8;
                    }
                    session.gatekeeper_id = gk_id;
                } else {
                    session.gatekeeper_id.copy_from_slice(&input_tok.bytes[32..48]);
                }
                session.flags.is_step2_hmac_done = true;

                Ok(SspiError::Ok)
            }
        }
    }

    fn delete_security_context(&self, context: &CtxtHandle) -> Result<(), SspiError> {
        self.sessions.lock().unwrap().remove(context);
        Ok(())
    }
}
