//! TCP test server binary for GateKeeper and GateKeeperPassport authentication.
//! Listens on port 6667 and processes AUTH challenge-response handshakes.

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};
use std::thread;
use std::sync::Arc;

use ircx_sspi::{
    GateKeeperSecurityProvider, GateKeeperPassportSecurityProvider, NtlmSecurityProvider,
    NtlmPassportSecurityProvider, SecurityProvider, CredHandle, CtxtHandle, SecBuffer,
    SecBufferType, SspiError,
};

#[derive(Clone)]
struct ServerAuth {
    gk_provider: Arc<GateKeeperSecurityProvider>,
    gkp_provider: Arc<GateKeeperPassportSecurityProvider>,
    ntlm_provider: Arc<NtlmSecurityProvider>,
    ntlm_passport_provider: Arc<NtlmPassportSecurityProvider>,
    gk_cred: CredHandle,
    gkp_cred: CredHandle,
    ntlm_cred: CredHandle,
    ntlm_passport_cred: CredHandle,
}

/// Helper to unescape specialized characters inside the IRC/MSN client-auth payload.
fn unescape(s: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b == b'\\' {
            if i + 1 < s.len() {
                let next = s[i + 1];
                match next {
                    b'r' => { bytes.push(b'\r'); i += 2; }
                    b'n' => { bytes.push(b'\n'); i += 2; }
                    b'0' => { bytes.push(b'\0'); i += 2; }
                    b'c' => { bytes.push(b','); i += 2; }
                    b't' => { bytes.push(b'\t'); i += 2; }
                    b'b' => { bytes.push(0x20); i += 2; }
                    b'\\' => { bytes.push(b'\\'); i += 2; }
                    _ => { bytes.push(b'\\'); i += 1; }
                }
            } else {
                bytes.push(b'\\');
                i += 1;
            }
        } else {
            bytes.push(b);
            i += 1;
        }
    }
    bytes
}

/// Helper to escape specialized characters when writing back to the client.
fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut s = Vec::new();
    for &b in bytes {
        match b {
            b'\r' => s.extend_from_slice(b"\\r"),
            b'\n' => s.extend_from_slice(b"\\n"),
            b'\0' => s.extend_from_slice(b"\\0"),
            b',' => s.extend_from_slice(b"\\c"),
            b'\t' => s.extend_from_slice(b"\\t"),
            0x20 => s.extend_from_slice(b"\\b"),
            b'\\' => s.extend_from_slice(b"\\\\"),
            _ => {
                s.push(b);
            }
        }
    }
    s
}

/// Helper to print a hex dump of a byte slice, similar to a hex editor.
fn hex_dump(bytes: &[u8]) {
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        print!("{:04x}:  ", offset);
        
        for j in 0..16 {
            if j < chunk.len() {
                print!("{:02x} ", chunk[j]);
            } else {
                print!("   ");
            }
            if j == 7 {
                print!(" ");
            }
        }
        
        print!(" |");
        for &b in chunk {
            if b >= 32 && b <= 126 {
                print!("{}", b as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
}

/// Parses standard MSN AUTH lines matching:
/// `AUTH GateKeeper(Passport)? [I|S] :*`
fn parse_auth_line(line: &[u8]) -> Option<(String, char, Vec<u8>)> {
    if !line.starts_with(b"AUTH ") {
        return None;
    }
    let rest = &line[5..];
    
    let space1 = rest.iter().position(|&x| x == b' ')?;
    let package_bytes = &rest[..space1];
    let package = String::from_utf8_lossy(package_bytes).into_owned();
    if package != "GateKeeper" && package != "GateKeeperPassport" && package != "NTLM" && package != "NTLMPassport" {
        return None;
    }
    
    let rest = &rest[space1 + 1..];
    let space2 = rest.iter().position(|&x| x == b' ');
    let (stage_bytes, payload_part) = if let Some(idx) = space2 {
        (&rest[..idx], &rest[idx + 1..])
    } else {
        (rest, &[][..])
    };
    
    if stage_bytes.is_empty() {
        return None;
    }
    let stage = stage_bytes[0] as char;
    if stage != 'I' && stage != 'S' {
        return None;
    }
    
    let payload = if payload_part.starts_with(b":") {
        &payload_part[1..]
    } else {
        payload_part
    };
    
    Some((package, stage, payload.to_vec()))
}

/// Buffer for incoming stream segments, splitting commands on \r or \n.
struct LineBuffer {
    buffer: Vec<u8>,
}

impl LineBuffer {
    fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    fn feed(&mut self, data: &[u8], mut on_line: impl FnMut(Vec<u8>)) {
        self.buffer.extend_from_slice(data);
        let mut start = 0;
        let mut i = 0;
        while i < self.buffer.len() {
            let b = self.buffer[i];
            if b == b'\r' || b == b'\n' {
                if i > start {
                    let slice = &self.buffer[start..i];
                    let is_empty = slice.iter().all(|&x| x == b' ' || x == b'\t' || x == b'\r' || x == b'\n');
                    if !is_empty {
                        on_line(slice.to_vec());
                    }
                }
                start = i + 1;
            }
            i += 1;
        }
        if start > 0 {
            self.buffer.drain(0..start);
        }
    }
}

enum AuthOutcome {
    Continue(Vec<u8>),
    Success(String),
}

fn main() {
    if let Err(e) = ircx_sspi::vault::ensure_master_key() {
        eprintln!("Failed to ensure master key: {:?}", e);
        std::process::exit(1);
    }

    let mut listeners = Vec::new();

    // Try IPv6 wildcard first (which might support dual-stack IPv4/IPv6 depending on OS)
    match TcpListener::bind("[::]:6667") {
        Ok(l) => {
            println!("Bound to [::]:6667 (IPv6 wildcard)");
            listeners.push(l);
        }
        Err(e) => {
            eprintln!("Failed to bind to [::]:6667: {}", e);
        }
    }

    // Try IPv4 wildcard
    match TcpListener::bind("0.0.0.0:6667") {
        Ok(l) => {
            println!("Bound to 0.0.0.0:6667 (IPv4 wildcard)");
            listeners.push(l);
        }
        Err(e) => {
            eprintln!("IPv4 wildcard bind status (might be already bound by dual-stack): {}", e);
        }
    }

    // If wildcard binds both failed, try loopbacks as fallback
    if listeners.is_empty() {
        match TcpListener::bind("[::1]:6667") {
            Ok(l) => {
                println!("Bound fallback to [::1]:6667 (IPv6 loopback)");
                listeners.push(l);
            }
            Err(e) => {
                eprintln!("Failed to bind to [::1]:6667: {}", e);
            }
        }
        match TcpListener::bind("127.0.0.1:6667") {
            Ok(l) => {
                println!("Bound fallback to 127.0.0.1:6667 (IPv4 loopback)");
                listeners.push(l);
            }
            Err(e) => {
                eprintln!("Failed to bind to 127.0.0.1:6667: {}", e);
            }
        }
    }

    if listeners.is_empty() {
        panic!("Failed to bind to port 6667 on any interface");
    }

    println!("IRCX SSPI Test Server listening on port 6667...");

    let gk_provider = Arc::new(GateKeeperSecurityProvider::new());
    let gkp_provider = Arc::new(GateKeeperPassportSecurityProvider::new());
    let ntlm_provider = Arc::new(NtlmSecurityProvider::new());
    let ntlm_passport_provider = Arc::new(NtlmPassportSecurityProvider::new());
    
    let mut gk_cred = CredHandle::default();
    gk_provider.acquire_credentials_handle(None, "GateKeeper", 2, None, &mut gk_cred)
        .expect("Failed to acquire GateKeeper credentials");
        
    let mut gkp_cred = CredHandle::default();
    gkp_provider.acquire_credentials_handle(None, "GateKeeperPassport", 2, None, &mut gkp_cred)
        .expect("Failed to acquire GateKeeperPassport credentials");

    let mut ntlm_cred = CredHandle::default();
    ntlm_provider.acquire_credentials_handle(None, "NTLM", 2, None, &mut ntlm_cred)
        .expect("Failed to acquire NTLM credentials");

    let mut ntlm_passport_cred = CredHandle::default();
    ntlm_passport_provider.acquire_credentials_handle(None, "NTLMPassport", 2, None, &mut ntlm_passport_cred)
        .expect("Failed to acquire NTLMPassport credentials");

    let auth = ServerAuth {
        gk_provider,
        gkp_provider,
        ntlm_provider,
        ntlm_passport_provider,
        gk_cred,
        gkp_cred,
        ntlm_cred,
        ntlm_passport_cred,
    };

    let last_listener = listeners.pop().unwrap();

    for listener in listeners {
        let auth = auth.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        let auth = auth.clone();
                        thread::spawn(move || {
                            handle_client(stream, auth);
                        });
                    }
                    Err(e) => {
                        eprintln!("Failed to accept connection: {}", e);
                    }
                }
            }
        });
    }

    for stream in last_listener.incoming() {
        match stream {
            Ok(stream) => {
                let auth = auth.clone();
                thread::spawn(move || {
                    handle_client(stream, auth);
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

fn handle_client(
    mut stream: TcpStream,
    auth: ServerAuth,
) {
    println!("New connection from: {}", stream.peer_addr().unwrap());
    let mut buffer = [0u8; 4096];
    let mut line_buf = LineBuffer::new();
    
    let mut active_package: Option<String> = None;
    let mut active_context: Option<CtxtHandle> = None;
    
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => {
                println!("Connection closed by client");
                break;
            }
            Ok(bytes_read) => {
                let data = &buffer[..bytes_read];
                let mut responses = Vec::new();
                
                line_buf.feed(data, |line| {
                    println!("<- {}", String::from_utf8_lossy(&line));
                    if let Some((package, stage, payload)) = parse_auth_line(&line) {
                        let unescaped = unescape(&payload);
                        if unescaped.starts_with(b"GKSSP") {
                            println!("--- GKSSP Incoming Hex Dump ({}) ---", package);
                            hex_dump(&unescaped);
                            println!("--------------------------------------");
                        }
                        
                        let res = process_auth(
                            &package,
                            stage,
                            &payload,
                            &mut active_package,
                            &mut active_context,
                            &auth,
                        );
                        match res {
                            Ok(AuthOutcome::Continue(out_bytes)) => {
                                if out_bytes.starts_with(b"GKSSP") {
                                    println!("--- GKSSP Outgoing Hex Dump ({}) ---", package);
                                    hex_dump(&out_bytes);
                                    println!("--------------------------------------");
                                }
                                let escaped = escape(&out_bytes);
                                let mut resp = Vec::new();
                                resp.extend_from_slice(b"AUTH ");
                                resp.extend_from_slice(package.as_bytes());
                                resp.extend_from_slice(b" S :");
                                resp.extend_from_slice(&escaped);
                                responses.push(resp);
                            }
                            Ok(AuthOutcome::Success(username)) => {
                                let mut resp = Vec::new();
                                resp.extend_from_slice(b"AUTH ");
                                resp.extend_from_slice(package.as_bytes());
                                resp.extend_from_slice(b" * ");
                                resp.extend_from_slice(username.as_bytes());
                                resp.extend_from_slice(b" 0");
                                responses.push(resp);
                            }
                            Err(e) => {
                                eprintln!("Authentication error: {:?}", e);
                                responses.push(b":server 910 * :Auth failed".to_vec());
                            }
                        }
                    }
                });
                
                for resp in responses {
                    println!("-> {}", String::from_utf8_lossy(&resp));
                    let mut out = resp;
                    out.extend_from_slice(b"\r\n");
                    if let Err(e) = stream.write_all(&out) {
                        eprintln!("Failed to write to stream: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Read error: {}", e);
                break;
            }
        }
    }
    
    cleanup_session(&mut active_package, &mut active_context, &auth);
}
 
fn process_auth(
    package: &str,
    stage: char,
    payload: &[u8],
    active_package: &mut Option<String>,
    active_context: &mut Option<CtxtHandle>,
    auth: &ServerAuth,
) -> Result<AuthOutcome, SspiError> {
    let unescaped = unescape(payload);
    
    if stage == 'I' {
        cleanup_session(active_package, active_context, auth);
        *active_package = Some(package.to_string());
        
        let mut new_context = CtxtHandle::default();
        let mut context_attr = 0;
        
        let input_buffers = if package == "GateKeeper" || package == "GateKeeperPassport" {
            vec![
                SecBuffer {
                    buffer_type: SecBufferType::Token,
                    bytes: unescaped,
                },
                SecBuffer {
                    buffer_type: SecBufferType::PkgParams,
                    bytes: b"localhost".to_vec(),
                },
                SecBuffer {
                    buffer_type: SecBufferType::PkgParams,
                    bytes: vec![1], // Compatibility flag (allow v1/v2)
                },
            ]
        } else {
            vec![
                SecBuffer {
                    buffer_type: SecBufferType::Token,
                    bytes: unescaped,
                }
            ]
        };
        
        let mut output_buffers = vec![
            SecBuffer {
                buffer_type: SecBufferType::Token,
                bytes: Vec::new(),
            }
        ];
        
        let res = match package {
            "GateKeeper" => {
                auth.gk_provider.accept_security_context(
                    &auth.gk_cred,
                    None,
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            "GateKeeperPassport" => {
                auth.gkp_provider.accept_security_context(
                    &auth.gkp_cred,
                    None,
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            "NTLM" => {
                auth.ntlm_provider.accept_security_context(
                    &auth.ntlm_cred,
                    None,
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            "NTLMPassport" => {
                auth.ntlm_passport_provider.accept_security_context(
                    &auth.ntlm_passport_cred,
                    None,
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            _ => return Err(SspiError::NotSupported),
        };
        
        match res {
            Ok(SspiError::ContinueNeeded) => {
                *active_context = Some(new_context);
                Ok(AuthOutcome::Continue(output_buffers[0].bytes.clone()))
            }
            Ok(SspiError::Ok) => {
                let username = get_username(package, &new_context, auth);
                let _ = match package {
                    "GateKeeper" => auth.gk_provider.delete_security_context(&new_context),
                    "GateKeeperPassport" => auth.gkp_provider.delete_security_context(&new_context),
                    "NTLM" => auth.ntlm_provider.delete_security_context(&new_context),
                    "NTLMPassport" => auth.ntlm_passport_provider.delete_security_context(&new_context),
                    _ => Ok(()),
                };
                *active_package = None;
                Ok(AuthOutcome::Success(username))
            }
            Ok(other) => Err(other),
            Err(e) => Err(e),
        }
    } else if stage == 'S' {
        let ctx = active_context.ok_or(SspiError::InvalidHandle)?;
        let act_pkg = active_package.as_ref().ok_or(SspiError::InvalidHandle)?;
        if act_pkg != package {
            return Err(SspiError::InvalidHandle);
        }
        
        let input_buffers = vec![
            SecBuffer {
                buffer_type: SecBufferType::Token,
                bytes: unescaped,
            }
        ];
        
        let mut output_buffers = vec![
            SecBuffer {
                buffer_type: SecBufferType::Token,
                bytes: Vec::new(),
            }
        ];
        
        let mut new_context = ctx;
        let mut context_attr = 0;
        
        let res = match package {
            "GateKeeper" => {
                auth.gk_provider.accept_security_context(
                    &auth.gk_cred,
                    Some(&ctx),
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            "GateKeeperPassport" => {
                auth.gkp_provider.accept_security_context(
                    &auth.gkp_cred,
                    Some(&ctx),
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            "NTLM" => {
                auth.ntlm_provider.accept_security_context(
                    &auth.ntlm_cred,
                    Some(&ctx),
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            "NTLMPassport" => {
                auth.ntlm_passport_provider.accept_security_context(
                    &auth.ntlm_passport_cred,
                    Some(&ctx),
                    &input_buffers,
                    0,
                    16,
                    &mut new_context,
                    &mut output_buffers,
                    &mut context_attr,
                )
            }
            _ => return Err(SspiError::NotSupported),
        };
        
        match res {
            Ok(SspiError::ContinueNeeded) => {
                *active_context = Some(new_context);
                Ok(AuthOutcome::Continue(output_buffers[0].bytes.clone()))
            }
            Ok(SspiError::Ok) => {
                let username = get_username(package, &new_context, auth);
                let _ = match package {
                    "GateKeeper" => auth.gk_provider.delete_security_context(&new_context),
                    "GateKeeperPassport" => auth.gkp_provider.delete_security_context(&new_context),
                    "NTLM" => auth.ntlm_provider.delete_security_context(&new_context),
                    "NTLMPassport" => auth.ntlm_passport_provider.delete_security_context(&new_context),
                    _ => Ok(()),
                };
                *active_context = None;
                *active_package = None;
                Ok(AuthOutcome::Success(username))
            }
            Ok(other) => {
                cleanup_session(active_package, active_context, auth);
                Err(other)
            }
            Err(e) => {
                cleanup_session(active_package, active_context, auth);
                Err(e)
            }
        }
    } else {
        Err(SspiError::NotSupported)
    }
}

fn cleanup_session(
    active_package: &mut Option<String>,
    active_context: &mut Option<CtxtHandle>,
    auth: &ServerAuth,
) {
    if let Some(ctx) = active_context.take() {
        if let Some(pkg) = active_package.as_ref() {
            let _ = match pkg.as_str() {
                "GateKeeper" => auth.gk_provider.delete_security_context(&ctx),
                "GateKeeperPassport" => auth.gkp_provider.delete_security_context(&ctx),
                "NTLM" => auth.ntlm_provider.delete_security_context(&ctx),
                "NTLMPassport" => auth.ntlm_passport_provider.delete_security_context(&ctx),
                _ => Ok(()),
            };
        }
    }
    *active_package = None;
}

fn get_username(
    package: &str,
    context: &CtxtHandle,
    auth: &ServerAuth,
) -> String {
    let base_name = if package == "GateKeeper" {
        let sessions = auth.gk_provider.sessions.lock().unwrap();
        if let Some(s) = sessions.get(context) {
            ircx_sspi::dll::format_gatekeeper_id(&s.gatekeeper_id)
        } else {
            "GateKeeperUser".to_string()
        }
    } else if package == "GateKeeperPassport" {
        let sessions = auth.gkp_provider.sessions.lock().unwrap();
        if let Some(comb) = sessions.get(context) {
            let mut gk_name = None;
            if let Some(gk_ctx) = comb.slot0_context {
                let gk_sessions = auth.gkp_provider.sub_gk.sessions.lock().unwrap();
                if let Some(s) = gk_sessions.get(&gk_ctx) {
                    gk_name = Some(ircx_sspi::dll::format_gatekeeper_id(&s.gatekeeper_id));
                }
            }
            let mut passport_name = None;
            if let Some(pass_ctx) = comb.slot1_context {
                let pass_sessions = auth.gkp_provider.sub_passport.sessions.lock().unwrap();
                if let Some(s) = pass_sessions.get(&pass_ctx) {
                    if !s.client_info.is_empty() {
                        passport_name = Some(s.client_info.clone());
                    }
                }
            }
            if passport_name.is_none() && comb.slot1_context.is_some() {
                passport_name = Some("PassportUser".to_string());
            }
            match (gk_name, passport_name) {
                (Some(g), Some(p)) => format!("{}+{}", g, p),
                (Some(g), None) => g,
                (None, Some(p)) => p,
                _ => "GateKeeperPassportUser".to_string(),
            }
        } else {
            "GateKeeperPassportUser".to_string()
        }
    } else if package == "NTLM" {
        let sessions = auth.ntlm_provider.sessions.lock().unwrap();
        if let Some(s) = sessions.get(context) {
            let uname = s.authenticated_username.clone().unwrap_or_else(|| "NtlmUser".to_string());
            let domain = s.authenticated_domain.clone().unwrap_or_default();
            if let Some(level) = s.authenticated_level {
                println!("[AUTH] Verified NTLM user '{}' [Domain: '{}', Level: '{}']", uname, domain, level);
            }
            let display_domain = if domain.is_empty() { "localhost".to_string() } else { domain };
            return format!("{}@{}", uname, display_domain);
        } else {
            "NtlmUser".to_string()
        }
    } else if package == "NTLMPassport" {
        let sessions = auth.ntlm_passport_provider.sessions.lock().unwrap();
        if let Some(comb) = sessions.get(context) {
            let mut ntlm_name = None;
            let mut ntlm_domain = None;
            if let Some(ntlm_ctx) = comb.slot0_context {
                let ntlm_sessions = auth.ntlm_passport_provider.sub_ntlm.sessions.lock().unwrap();
                if let Some(s) = ntlm_sessions.get(&ntlm_ctx) {
                    ntlm_name = s.authenticated_username.clone();
                    ntlm_domain = s.authenticated_domain.clone();
                    if let (Some(level), Some(domain)) = (s.authenticated_level, &s.authenticated_domain) {
                        println!("[AUTH] Verified NTLMPassport sub-NTLM user '{}' [Domain: '{}', Level: '{}']", s.authenticated_username.as_deref().unwrap_or(""), domain, level);
                    }
                }
            }
            if ntlm_name.is_none() {
                ntlm_name = Some("NtlmUser".to_string());
            }
            
            let mut passport_name = None;
            if let Some(pass_ctx) = comb.slot1_context {
                let pass_sessions = auth.ntlm_passport_provider.sub_passport.sessions.lock().unwrap();
                if let Some(s) = pass_sessions.get(&pass_ctx) {
                    if !s.client_info.is_empty() {
                        passport_name = Some(s.client_info.clone());
                    }
                }
            }
            if passport_name.is_none() && comb.slot1_context.is_some() {
                passport_name = Some("PassportUser".to_string());
            }
            let display_domain = match &ntlm_domain {
                Some(d) if !d.is_empty() => d.clone(),
                _ => "localhost".to_string(),
            };
            let ntlm_part = match (ntlm_name, passport_name) {
                (Some(n), Some(p)) => format!("{}+{}", n, p),
                (Some(n), None) => n,
                (None, Some(p)) => p,
                _ => "NtlmUser+PassportUser".to_string(),
            };
            return format!("{}@{}", ntlm_part, display_domain);
        } else {
            "NtlmUser+PassportUser".to_string()
        }
    } else {
        "UnknownUser".to_string()
    };
    format!("{}@{}", base_name, package)
}
