//! TCP client for testing GateKeeper and GateKeeperPassport SSPI handshakes with the server.

use std::net::TcpStream;
use std::io::{Read, Write};
use ircx_sspi::{
    GateKeeperSecurityProvider, GateKeeperPassportSecurityProvider, SecurityProvider,
    CredHandle, CtxtHandle, SecBuffer, SecBufferType, SspiError,
};

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

fn read_line(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = [0u8; 1];
    let mut line_bytes = Vec::new();
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

    println!("\n=== GateKeeperPassport End-to-End Handshake ===");
    test_gatekeeper_passport();
}

fn test_gatekeeper() {
    let mut stream = TcpStream::connect("127.0.0.1:6667").expect("Failed to connect to server");
    println!("Connected to server on port 6667.");

    let gk_provider = GateKeeperSecurityProvider::new();
    let mut client_cred = CredHandle::default();
    gk_provider.acquire_credentials_handle(None, "GateKeeper", 1, None, &mut client_cred).unwrap();

    let gk_id = b"GK_CLIENT_ID_TOK";
    let hostname = b"localhost";

    let client_input = vec![
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: gk_id.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
    ];
    let mut client_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx = CtxtHandle::default();
    let mut client_attr = 0u32;

    let res_c1 = gk_provider.initialize_security_context(
        &client_cred,
        None,
        None,
        0,
        16,
        &client_input,
        &mut client_ctx,
        &mut client_output,
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let step1_token = client_output[0].bytes.clone();
    let escaped_token_1 = escape(&step1_token);
    
    let mut msg1 = b"AUTH GateKeeper I :".to_vec();
    msg1.extend_from_slice(&escaped_token_1);
    msg1.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg1).trim());
    stream.write_all(&msg1).unwrap();

    let reply1 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply1));

    // Reply is: AUTH GateKeeper S :<escaped_server_challenge>
    assert!(reply1.starts_with(b"AUTH GateKeeper S :"));
    let escaped_challenge = &reply1[b"AUTH GateKeeper S :".len()..];
    let challenge_token = unescape(escaped_challenge);

    let client_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: challenge_token },
    ];
    let mut client_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = gk_provider.initialize_security_context(
        &client_cred,
        Some(&client_ctx),
        None,
        0,
        16,
        &client_input_2,
        &mut client_ctx_2,
        &mut client_output_2,
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c2, SspiError::Ok);
    let step2_token = client_output_2[0].bytes.clone();
    let escaped_token_2 = escape(&step2_token);

    let mut msg2 = b"AUTH GateKeeper S :".to_vec();
    msg2.extend_from_slice(&escaped_token_2);
    msg2.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg2).trim());
    stream.write_all(&msg2).unwrap();

    let reply2 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply2));

    assert!(reply2.starts_with(b"AUTH GateKeeper * "));
    assert!(reply2.ends_with(b" 0"));
    println!("GateKeeper Handshake successful!");
}

fn test_gatekeeper_passport() {
    let mut stream = TcpStream::connect("127.0.0.1:6667").expect("Failed to connect to server");
    println!("Connected to server on port 6667.");

    let gkp_provider = GateKeeperPassportSecurityProvider::new();
    let mut client_cred = CredHandle::default();
    gkp_provider.acquire_credentials_handle(None, "GateKeeperPassport", 1, None, &mut client_cred).unwrap();

    let gk_id = b"GK_CLIENT_ID_TOK";
    let hostname = b"localhost";

    let client_input = vec![
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: gk_id.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
    ];
    let mut client_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx = CtxtHandle::default();
    let mut client_attr = 0u32;

    let res_c1 = gkp_provider.initialize_security_context(
        &client_cred,
        None,
        None,
        0,
        16,
        &client_input,
        &mut client_ctx,
        &mut client_output,
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let step1_token = client_output[0].bytes.clone();
    let escaped_token_1 = escape(&step1_token);
    
    let mut msg1 = b"AUTH GateKeeperPassport I :".to_vec();
    msg1.extend_from_slice(&escaped_token_1);
    msg1.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg1).trim());
    stream.write_all(&msg1).unwrap();

    let reply1 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply1));

    assert!(reply1.starts_with(b"AUTH GateKeeperPassport S :"));
    let escaped_challenge = &reply1[b"AUTH GateKeeperPassport S :".len()..];
    let challenge_token = unescape(escaped_challenge);

    let client_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: challenge_token },
    ];
    let mut client_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = gkp_provider.initialize_security_context(
        &client_cred,
        Some(&client_ctx),
        None,
        0,
        16,
        &client_input_2,
        &mut client_ctx_2,
        &mut client_output_2,
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c2, SspiError::ContinueNeeded);
    let step2_token = client_output_2[0].bytes.clone();
    let escaped_token_2 = escape(&step2_token);

    let mut msg2 = b"AUTH GateKeeperPassport S :".to_vec();
    msg2.extend_from_slice(&escaped_token_2);
    msg2.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg2).trim());
    stream.write_all(&msg2).unwrap();

    let reply2 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply2));

    assert!(reply2.starts_with(b"AUTH GateKeeperPassport S :"));
    let escaped_ok = &reply2[b"AUTH GateKeeperPassport S :".len()..];
    let ok_bytes = unescape(escaped_ok);
    assert_eq!(ok_bytes, b"OK");

    // Initiate Passport Phase
    let passport_ticket = vec![0xBBu8; 200];
    let client_input_p = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: b"OK".to_vec() },
        SecBuffer { buffer_type: SecBufferType::Token, bytes: passport_ticket },
    ];
    let mut client_output_p = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 256] },
    ];
    let mut client_ctx_3 = client_ctx_2;

    let res_c3 = gkp_provider.initialize_security_context(
        &client_cred,
        Some(&client_ctx_2),
        None,
        0,
        16,
        &client_input_p,
        &mut client_ctx_3,
        &mut client_output_p,
        &mut client_attr,
    ).unwrap();

    assert_eq!(res_c3, SspiError::Ok);
    let step3_token = client_output_p[0].bytes.clone();
    let escaped_token_3 = escape(&step3_token);

    let mut msg3 = b"AUTH GateKeeperPassport S :".to_vec();
    msg3.extend_from_slice(&escaped_token_3);
    msg3.extend_from_slice(b"\r\n");
    println!("Client: {}", String::from_utf8_lossy(&msg3).trim());
    stream.write_all(&msg3).unwrap();

    let reply3 = read_line(&mut stream);
    println!("Server: {}", String::from_utf8_lossy(&reply3));

    assert!(reply3.starts_with(b"AUTH GateKeeperPassport * "));
    assert!(reply3.ends_with(b" 0"));
    println!("GateKeeperPassport Handshake successful!");
}
