//! TCP client for testing GateKeeper and GateKeeperPassport SSPI handshakes with the server.

use std::net::TcpStream;
use std::io::{Read, Write};
use ircx_sspi::{
    GateKeeperSecurityProvider, NtlmSecurityProvider,
    SecurityProvider, CredHandle, CtxtHandle, SecBuffer,
    SecBufferType, SspiError,
};

fn unescape(s: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
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

fn escape(bytes: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = Vec::new();
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

fn read_line(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = [0u8; 1];
    let mut line_bytes: Vec<u8> = Vec::new();
    loop {
        match stream.read_exact(&mut buffer) {
            Ok(_) => {
                let b = buffer[0];
                if b == b'\n' {
                    break;
                }
                if b != b'\r' {
                    line_bytes.push(b);
                }
            }
            Err(e) => {
                panic!("Failed to read from TCP stream: {}", e);
            }
        }
    }
    line_bytes
}

fn main() {
    println!("=== GateKeeper End-to-End Handshake ===");
    test_gatekeeper();

    println!("\n=== NTLM End-to-End Handshake ===");
    test_ntlm();
}

fn test_gatekeeper() {
    let mut stream = TcpStream::connect("127.0.0.1:6667").expect("Failed to connect to server");
    println!("Connected to server on port 6667.");

    let gk_provider = GateKeeperSecurityProvider::new();
    let mut client_cred = CredHandle { dw_lower: 0, dw_upper: 0 };
    gk_provider.acquire_credentials_handle(None, "GateKeeper", 1, None, &mut client_cred).unwrap();

    let gk_id = b"GK_CLIENT_ID_TOK";
    let hostname = b"localhost";

    let client_input: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: gk_id.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
    ];
    let mut client_output: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx = CtxtHandle { dw_lower: 0, dw_upper: 0 };
    let mut client_attr = 0u32;

    let res_c1 = gk_provider.initialize_security_context(
        &client_cred,
        None,
        None,
        0,
        16,
        client_input.as_slice(),
        &mut client_ctx,
        client_output.as_mut_slice(),
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let step1_token = client_output[0].bytes.clone();
    let escaped_token_1 = escape(&step1_token);
    
    let mut msg1 = b"AUTH GateKeeper I :".to_vec();
    msg1.extend_from_slice(&escaped_token_1);
    msg1.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg1).as_ref().trim());
    stream.write_all(&msg1).unwrap();

    let reply1 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply1));

    // Reply is: AUTH GateKeeper S :<escaped_server_challenge>
    assert!(reply1.as_slice().starts_with(b"AUTH GateKeeper S :"));
    let escaped_challenge = &reply1[b"AUTH GateKeeper S :".len()..];
    let challenge_token = unescape(escaped_challenge);

    let client_input_2: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: challenge_token },
    ];
    let mut client_output_2: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = gk_provider.initialize_security_context(
        &client_cred,
        Some(&client_ctx),
        None,
        0,
        16,
        client_input_2.as_slice(),
        &mut client_ctx_2,
        client_output_2.as_mut_slice(),
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c2, SspiError::Ok);
    let step2_token = client_output_2[0].bytes.clone();
    let escaped_token_2 = escape(&step2_token);

    let mut msg2 = b"AUTH GateKeeper S :".to_vec();
    msg2.extend_from_slice(&escaped_token_2);
    msg2.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg2).as_ref().trim());
    stream.write_all(&msg2).unwrap();

    let reply2 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply2));

    assert!(reply2.as_slice().starts_with(b"AUTH GateKeeper * "));
    assert!(reply2.as_slice().ends_with(b" 0"));
    println!("GateKeeper Handshake successful!");
}

fn test_ntlm() {
    let mut stream = TcpStream::connect("127.0.0.1:6667").expect("Failed to connect to server");
    println!("Connected to server on port 6667.");

    let ntlm_provider = NtlmSecurityProvider::new();
    let mut client_cred = CredHandle { dw_lower: 0, dw_upper: 0 };
    ntlm_provider.acquire_credentials_handle(None, "NTLM", 1, None, &mut client_cred).unwrap();

    let client_input: Vec<SecBuffer> = vec![];
    let mut client_output: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 1024] },
    ];
    let mut client_ctx = CtxtHandle { dw_lower: 0, dw_upper: 0 };
    let mut client_attr = 0u32;

    let res_c1 = ntlm_provider.initialize_security_context(
        &client_cred,
        None,
        None,
        0,
        16,
        client_input.as_slice(),
        &mut client_ctx,
        client_output.as_mut_slice(),
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let step1_token = client_output[0].bytes.clone();
    let escaped_token_1 = escape(&step1_token);
    
    let mut msg1 = b"AUTH NTLM I :".to_vec();
    msg1.extend_from_slice(&escaped_token_1);
    msg1.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg1).as_ref().trim());
    stream.write_all(&msg1).unwrap();

    let reply1 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply1));

    assert!(reply1.as_slice().starts_with(b"AUTH NTLM S :"));
    let escaped_challenge = &reply1[b"AUTH NTLM S :".len()..];
    let challenge_token = unescape(escaped_challenge);

    let client_input_2: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: challenge_token },
    ];
    let mut client_output_2: Vec<SecBuffer> = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 1024] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = ntlm_provider.initialize_security_context(
        &client_cred,
        Some(&client_ctx),
        None,
        0,
        16,
        client_input_2.as_slice(),
        &mut client_ctx_2,
        client_output_2.as_mut_slice(),
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c2, SspiError::Ok);
    let step2_token = client_output_2[0].bytes.clone();
    let escaped_token_2 = escape(&step2_token);

    let mut msg2 = b"AUTH NTLM S :".to_vec();
    msg2.extend_from_slice(&escaped_token_2);
    msg2.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg2).as_ref().trim());
    stream.write_all(&msg2).unwrap();

    let reply2 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply2));

    assert!(reply2.as_slice().starts_with(b"AUTH NTLM * "));
    assert!(reply2.as_slice().ends_with(b" 0"));
    println!("NTLM Handshake successful!");
}
