//! # MSN Chat SSPI Dynamic Library Integration Test Suite
//!
//! Exclusively loads and tests the compiled `ircx_sspi` dynamic library (DLL / shared library)
//! through the standard Win32 Security Support Provider Interface (SSPI).

#![allow(non_snake_case)]

use ircx_sspi::{
    CredHandle, CtxtHandle, SecBuffer, SecBufferType, SspiError,
};

/// Dynamic function pointers for the SSPI table exports
type AcquireCredentialsHandleAFn = unsafe extern "system" fn(
    pszPrincipal: *const i8,
    pszPackage: *const i8,
    fCredentialUse: u32,
    pvLogonID: *const std::ffi::c_void,
    pAuthData: *const std::ffi::c_void,
    pGetKeyFn: *const std::ffi::c_void,
    pvGetKeyArgument: *const std::ffi::c_void,
    phCredential: *mut CredHandle,
    ptsExpiry: *mut u64,
) -> i32;

type FreeCredentialsHandleFn = unsafe extern "system" fn(
    phCredential: *const CredHandle,
) -> i32;

type InitializeSecurityContextAFn = unsafe extern "system" fn(
    phCredential: *const CredHandle,
    phContext: *const CtxtHandle,
    pszTargetName: *const i8,
    fContextReq: u32,
    Reserved1: u32,
    TargetDataRep: u32,
    pInput: *const ircx_sspi::dll::SecBufferDesc,
    Reserved2: u32,
    phNewContext: *mut CtxtHandle,
    pOutput: *mut ircx_sspi::dll::SecBufferDesc,
    pfContextAttr: *mut u32,
    ptsExpiry: *mut u64,
) -> i32;

type AcceptSecurityContextFn = unsafe extern "system" fn(
    phCredential: *const CredHandle,
    phContext: *const CtxtHandle,
    pInput: *const ircx_sspi::dll::SecBufferDesc,
    fContextReq: u32,
    TargetDataRep: u32,
    phNewContext: *mut CtxtHandle,
    pOutput: *mut ircx_sspi::dll::SecBufferDesc,
    pfContextAttr: *mut u32,
    ptsExpiry: *mut u64,
) -> i32;

type DeleteSecurityContextFn = unsafe extern "system" fn(
    phContext: *const CtxtHandle,
) -> i32;

type QueryContextAttributesAFn = unsafe extern "system" fn(
    phContext: *const CtxtHandle,
    ulAttribute: u32,
    pBuffer: *mut std::ffi::c_void,
) -> i32;

type FreeContextBufferFn = unsafe extern "system" fn(
    pv: *mut std::ffi::c_void,
) -> i32;

type EnumerateSecurityPackagesAFn = unsafe extern "system" fn(
    pcPackages: *mut u32,
    ppPackageInfo: *mut *mut ircx_sspi::dll::SecPkgInfoA,
) -> i32;

// ============================================================================
// Platform-Specific Dynamic Loader Bindings
// ============================================================================

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> *mut std::ffi::c_void;
    fn GetProcAddress(hModule: *mut std::ffi::c_void, lpProcName: *const u8) -> *mut std::ffi::c_void;
    fn FreeLibrary(hModule: *mut std::ffi::c_void) -> i32;
    fn GetLastError() -> u32;
}

#[cfg(not(windows))]
unsafe extern "C" {
    fn dlopen(filename: *const u8, flag: std::ffi::c_int) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const u8) -> *mut std::ffi::c_void;
    fn dlclose(handle: *mut std::ffi::c_void) -> std::ffi::c_int;
    fn dlerror() -> *const u8;
}

#[cfg(not(windows))]
const RTLD_NOW: std::ffi::c_int = 2;

// ============================================================================
// SSPI Interface Wrapper
// ============================================================================

struct SspiInterface {
    h_module: *mut std::ffi::c_void,
    table: &'static ircx_sspi::dll::SecurityFunctionTableA,
}

impl SspiInterface {
    fn load() -> Self {
        unsafe {
            #[cfg(windows)]
            {
                let mut h_module = LoadLibraryA("target\\debug\\ircx_sspi.dll\0".as_ptr());
                if h_module.is_null() {
                    h_module = LoadLibraryA("ircx_sspi.dll\0".as_ptr());
                }
                if h_module.is_null() {
                    h_module = LoadLibraryA("target\\release\\ircx_sspi.dll\0".as_ptr());
                }
                if h_module.is_null() {
                    panic!("Failed to load ircx_sspi.dll. GetLastError: {}", GetLastError());
                }
                
                let init_addr = GetProcAddress(h_module, "InitSecurityInterfaceA\0".as_ptr());
                if init_addr.is_null() {
                    panic!("InitSecurityInterfaceA not found in DLL");
                }
                
                let init_fn: unsafe extern "system" fn() -> *const ircx_sspi::dll::SecurityFunctionTableA =
                    std::mem::transmute(init_addr);
                let table_ptr = init_fn();
                if table_ptr.is_null() {
                    panic!("InitSecurityInterfaceA returned null");
                }
                
                Self {
                    h_module,
                    table: &*table_ptr,
                }
            }

            #[cfg(not(windows))]
            {
                let mut h_module = dlopen("target/debug/libircx_sspi.so\0".as_ptr(), RTLD_NOW);
                if h_module.is_null() {
                    h_module = dlopen("libircx_sspi.so\0".as_ptr(), RTLD_NOW);
                }
                if h_module.is_null() {
                    h_module = dlopen("target/release/libircx_sspi.so\0".as_ptr(), RTLD_NOW);
                }
                if h_module.is_null() {
                    let err_ptr = dlerror();
                    let err_str = if err_ptr.is_null() {
                        "Unknown error".to_string()
                    } else {
                        std::ffi::CStr::from_ptr(err_ptr as *const i8).to_string_lossy().into_owned()
                    };
                    panic!("Failed to load libircx_sspi.so. dlerror: {}", err_str);
                }
                
                let init_addr = dlsym(h_module, "InitSecurityInterfaceA\0".as_ptr());
                if init_addr.is_null() {
                    panic!("InitSecurityInterfaceA not found in shared library");
                }
                
                let init_fn: unsafe extern "system" fn() -> *const ircx_sspi::dll::SecurityFunctionTableA =
                    std::mem::transmute(init_addr);
                let table_ptr = init_fn();
                if table_ptr.is_null() {
                    panic!("InitSecurityInterfaceA returned null");
                }
                
                Self {
                    h_module,
                    table: &*table_ptr,
                }
            }
        }
    }

    unsafe fn acquire_credentials_handle(
        &self,
        principal: Option<&str>,
        package: &str,
        cred_use: u32,
        auth_data: Option<&[u8]>,
        handle: &mut CredHandle,
    ) -> Result<(), SspiError> {
        let psz_principal = principal.map(|s| {
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0);
            bytes
        });
        let principal_ptr = psz_principal.as_ref().map(|b| b.as_ptr() as *const i8).unwrap_or(std::ptr::null());
        
        let mut pkg_bytes = package.as_bytes().to_vec();
        pkg_bytes.push(0);
        let pkg_ptr = pkg_bytes.as_ptr() as *const i8;
        
        let auth_data_ptr = auth_data.map(|d| d.as_ptr() as *const std::ffi::c_void).unwrap_or(std::ptr::null());
        
        let func: AcquireCredentialsHandleAFn = unsafe { std::mem::transmute(self.table.acquire_credentials_handle_a) };
        let mut expiry = 0u64;
        let res = unsafe {
            func(
                principal_ptr,
                pkg_ptr,
                cred_use,
                std::ptr::null(),
                auth_data_ptr,
                std::ptr::null(),
                std::ptr::null(),
                handle,
                &mut expiry,
            )
        };
        
        match map_sspi_code(res) {
            Ok(SspiError::Ok) => Ok(()),
            Ok(e) => Err(e),
            Err(e) => Err(e),
        }
    }

    unsafe fn free_credentials_handle(&self, handle: &CredHandle) -> Result<(), SspiError> {
        let func: FreeCredentialsHandleFn = unsafe { std::mem::transmute(self.table.free_credentials_handle) };
        let res = unsafe { func(handle) };
        match map_sspi_code(res) {
            Ok(SspiError::Ok) => Ok(()),
            Ok(e) => Err(e),
            Err(e) => Err(e),
        }
    }

    unsafe fn initialize_security_context(
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
    ) -> Result<SspiError, SspiError> {
        let target_name_bytes = target_name.map(|s| {
            let mut bytes = s.as_bytes().to_vec();
            bytes.push(0);
            bytes
        });
        let target_ptr = target_name_bytes.as_ref().map(|b| b.as_ptr() as *const i8).unwrap_or(std::ptr::null());
        
        let context_ptr = context.map(|c| c as *const CtxtHandle).unwrap_or(std::ptr::null());
        
        let ffi_input = FfiBuffers::new(input_buffers);
        let input_desc_ptr = if input_buffers.is_empty() {
            std::ptr::null()
        } else {
            &ffi_input.desc as *const ircx_sspi::dll::SecBufferDesc
        };
        
        let out_specs: Vec<(SecBufferType, usize)> = output_buffers.iter()
            .map(|b| (b.buffer_type, b.bytes.len()))
            .collect();
        let mut ffi_output = FfiBuffers::new_with_capacity(&out_specs);
        let output_desc_ptr = &mut ffi_output.desc as *mut ircx_sspi::dll::SecBufferDesc;
        
        let func: InitializeSecurityContextAFn = unsafe { std::mem::transmute(self.table.initialize_security_context_a) };
        let mut expiry = 0u64;
        let res = unsafe {
            func(
                credential,
                context_ptr,
                target_ptr,
                context_req,
                0,
                target_data_rep,
                input_desc_ptr,
                0,
                new_context,
                output_desc_ptr,
                context_attr,
                &mut expiry,
            )
        };
        
        let updated_output = ffi_output.to_rust_buffers();
        for (dest, src) in output_buffers.iter_mut().zip(updated_output) {
            *dest = src;
        }
        
        map_sspi_code(res)
    }

    unsafe fn accept_security_context(
        &self,
        credential: &CredHandle,
        context: Option<&CtxtHandle>,
        input_buffers: &[SecBuffer],
        context_req: u32,
        target_data_rep: u32,
        new_context: &mut CtxtHandle,
        output_buffers: &mut [SecBuffer],
        context_attr: &mut u32,
    ) -> Result<SspiError, SspiError> {
        let context_ptr = context.map(|c| c as *const CtxtHandle).unwrap_or(std::ptr::null());
        
        let ffi_input = FfiBuffers::new(input_buffers);
        let input_desc_ptr = if input_buffers.is_empty() {
            std::ptr::null()
        } else {
            &ffi_input.desc as *const ircx_sspi::dll::SecBufferDesc
        };
        
        let out_specs: Vec<(SecBufferType, usize)> = output_buffers.iter()
            .map(|b| (b.buffer_type, b.bytes.len()))
            .collect();
        let mut ffi_output = FfiBuffers::new_with_capacity(&out_specs);
        let output_desc_ptr = &mut ffi_output.desc as *mut ircx_sspi::dll::SecBufferDesc;
        
        let func: AcceptSecurityContextFn = unsafe { std::mem::transmute(self.table.accept_security_context) };
        let mut expiry = 0u64;
        let res = unsafe {
            func(
                credential,
                context_ptr,
                input_desc_ptr,
                context_req,
                target_data_rep,
                new_context,
                output_desc_ptr,
                context_attr,
                &mut expiry,
            )
        };
        
        let updated_output = ffi_output.to_rust_buffers();
        for (dest, src) in output_buffers.iter_mut().zip(updated_output) {
            *dest = src;
        }
        
        map_sspi_code(res)
    }

    unsafe fn delete_security_context(&self, context: &CtxtHandle) -> Result<(), SspiError> {
        let func: DeleteSecurityContextFn = unsafe { std::mem::transmute(self.table.delete_security_context) };
        let res = unsafe { func(context) };
        match map_sspi_code(res) {
            Ok(SspiError::Ok) => Ok(()),
            Ok(e) => Err(e),
            Err(e) => Err(e),
        }
    }

    unsafe fn query_context_attributes(&self, context: &CtxtHandle, attribute: u32) -> Result<String, SspiError> {
        if attribute == ircx_sspi::dll::SECPKG_ATTR_NAMES {
            let mut names = ircx_sspi::dll::SecPkgContext_NamesA {
                sUserName: std::ptr::null_mut(),
            };
            
            let func: QueryContextAttributesAFn = unsafe { std::mem::transmute(self.table.query_context_attributes_a) };
            let res = unsafe {
                func(
                    context,
                    attribute,
                    &mut names as *mut _ as *mut std::ffi::c_void,
                )
            };
            
            match map_sspi_code(res) {
                Ok(SspiError::Ok) => {
                    if names.sUserName.is_null() {
                        return Err(SspiError::InvalidHandle);
                    }
                    let username = unsafe { std::ffi::CStr::from_ptr(names.sUserName).to_string_lossy().into_owned() };
                    
                    let free_func: FreeContextBufferFn = unsafe { std::mem::transmute(self.table.free_context_buffer) };
                    unsafe { free_func(names.sUserName as *mut std::ffi::c_void); }
                    
                    Ok(username)
                }
                Ok(e) => Err(e),
                Err(e) => Err(e),
            }
        } else {
            Err(SspiError::NotSupported)
        }
    }

    unsafe fn enumerate_security_packages(&self) -> Result<Vec<(String, String, u32, u16, u16, u32)>, SspiError> {
        let func: EnumerateSecurityPackagesAFn = unsafe { std::mem::transmute(self.table.enumerate_security_packages_a) };
        let mut count = 0u32;
        let mut pkg_info = std::ptr::null_mut();
        let res = unsafe { func(&mut count, &mut pkg_info) };
        match map_sspi_code(res) {
            Ok(SspiError::Ok) => {
                if pkg_info.is_null() || count == 0 {
                    return Ok(Vec::new());
                }
                let mut pkgs = Vec::new();
                for i in 0..count {
                    let info = unsafe { &*pkg_info.add(i as usize) };
                    let name = unsafe { std::ffi::CStr::from_ptr(info.name).to_string_lossy().into_owned() };
                    let comment = unsafe { std::ffi::CStr::from_ptr(info.comment).to_string_lossy().into_owned() };
                    pkgs.push((name, comment, info.f_capabilities, info.w_version, info.w_rpcid, info.cb_max_token));
                }
                let free_func: FreeContextBufferFn = unsafe { std::mem::transmute(self.table.free_context_buffer) };
                unsafe { free_func(pkg_info as *mut std::ffi::c_void); }
                Ok(pkgs)
            }
            Ok(e) => Err(e),
            Err(e) => Err(e),
        }
    }
}

impl Drop for SspiInterface {
    fn drop(&mut self) {
        unsafe {
            #[cfg(windows)]
            FreeLibrary(self.h_module);
            #[cfg(not(windows))]
            dlclose(self.h_module);
        }
    }
}

// ============================================================================
// FFI Buffer Allocation Orchestrator
// ============================================================================

struct FfiBuffers {
    c_buffers: Vec<ircx_sspi::dll::SecBuffer>,
    _data: Vec<Vec<u8>>,
    desc: ircx_sspi::dll::SecBufferDesc,
}

impl FfiBuffers {
    fn new(buffers: &[SecBuffer]) -> Self {
        let mut c_buffers = Vec::new();
        let mut _data = Vec::new();
        
        for buf in buffers {
            let mut bytes = buf.bytes.clone();
            let ptr = bytes.as_mut_ptr();
            let len = bytes.len() as u32;
            let ty = match buf.buffer_type {
                SecBufferType::Token => 2,
                SecBufferType::PkgParams => 3,
                SecBufferType::Other => 0,
            };
            
            c_buffers.push(ircx_sspi::dll::SecBuffer {
                cb_buffer: len,
                buffer_type: ty,
                pv_buffer: ptr,
            });
            _data.push(bytes);
        }
        
        let desc = ircx_sspi::dll::SecBufferDesc {
            ul_version: 0,
            c_buffers: c_buffers.len() as u32,
            p_buffers: c_buffers.as_mut_ptr(),
        };
        
        Self {
            c_buffers,
            _data,
            desc,
        }
    }

    fn new_with_capacity(buffer_specs: &[(SecBufferType, usize)]) -> Self {
        let mut c_buffers = Vec::new();
        let mut _data = Vec::new();
        
        for &(ty, cap) in buffer_specs {
            let mut bytes = vec![0u8; cap];
            let ptr = bytes.as_mut_ptr();
            let raw_ty = match ty {
                SecBufferType::Token => 2,
                SecBufferType::PkgParams => 3,
                SecBufferType::Other => 0,
            };
            
            c_buffers.push(ircx_sspi::dll::SecBuffer {
                cb_buffer: cap as u32,
                buffer_type: raw_ty,
                pv_buffer: ptr,
            });
            _data.push(bytes);
        }
        
        let desc = ircx_sspi::dll::SecBufferDesc {
            ul_version: 0,
            c_buffers: c_buffers.len() as u32,
            p_buffers: c_buffers.as_mut_ptr(),
        };
        
        Self {
            c_buffers,
            _data,
            desc,
        }
    }

    fn to_rust_buffers(&self) -> Vec<SecBuffer> {
        let mut rust_bufs = Vec::new();
        for (i, c_buf) in self.c_buffers.iter().enumerate() {
            let bytes = self._data[i][..c_buf.cb_buffer as usize].to_vec();
            rust_bufs.push(SecBuffer {
                buffer_type: SecBufferType::from(c_buf.buffer_type),
                bytes,
            })
        }
        rust_bufs
    }
}

// ============================================================================
// SSPI Helper Conversions
// ============================================================================

fn map_sspi_code(code: i32) -> Result<SspiError, SspiError> {
    match code {
        0 => Ok(SspiError::Ok),
        0x00090312 => Ok(SspiError::ContinueNeeded),
        -2146893043 => Err(SspiError::UnknownCredentials),
        -2146893055 => Err(SspiError::InvalidHandle),
        -2146893053 => Err(SspiError::TargetUnknown),
        -2146893054 => Err(SspiError::NotSupported),
        -2146893048 => Err(SspiError::InvalidToken),
        -2146893044 => Err(SspiError::LogonDenied),
        _ => Err(SspiError::InvalidHandle),
    }
}

// ============================================================================
// Console Logging and Simulation Suite Runner
// ============================================================================

fn print_header(title: &str) {
    println!("\x1b[1;36m================================================================================\x1b[0m");
    println!("\x1b[1;35m  ★ {} ★\x1b[0m", title);
    println!("\x1b[1;36m================================================================================\x1b[0m");
}

fn print_success(msg: &str) {
    println!("\x1b[1;32m[✔] Success: {}\x1b[0m", msg);
}

fn print_info(msg: &str) {
    println!("\x1b[1;34m[ℹ] Info: {}\x1b[0m", msg);
}

fn dump_buffer(name: &str, buf: &[u8]) {
    print!("    \x1b[1;33m{:<12} ({} bytes):\x1b[0m [", name, buf.len());
    for chunk in buf.chunks(16) {
        for b in chunk {
            print!("{:02X} ", b);
        }
    }
    println!("]");
    let text: String = buf.iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect();
    println!("    \x1b[1;30mASCII Interpretation: {}\x1b[0m", text);
}

fn main() {
    print_header("MSN CHAT SSPI DLL NATIVE HANDSHAKE SIMULATION SUITE");

    // Ensure the default user "TestUser" exists in the vault for the integration tests
    if let Err(e) = ircx_sspi::vault::add_user_to_vault("TestUser", "password", "", ircx_sspi::vault::UserLevel::Admin) {
        eprintln!("Warning: Failed to setup test user in vault: {:?}", e);
    }

    // Load the DLL dynamically
    let sspi = SspiInterface::load();
    print_success("SSPI DLL dynamically loaded and InitSecurityInterfaceA resolved.");

    // 0. Test Security Package Enumeration
    test_enumerate_packages(&sspi);

    // 1. Test GateKeeper Security Provider Handshake
    test_gatekeeper_handshake(&sspi);

    // 1b. Test GateKeeper Legacy Version 1 Security Provider Handshake
    test_gatekeeper_legacy_v1_handshake(&sspi);

    // 2. Test NTLM Security Provider Handshake
    test_ntlm_handshake(&sspi);

    print_header("ALL DLL SSPI AUTHENTICATION HANDSHAKES VERIFIED SUCCESSFULLY");
}

fn test_enumerate_packages(sspi: &SspiInterface) {
    print_header("0. ENUMERATE SECURITY PACKAGES");
    let pkgs = unsafe { sspi.enumerate_security_packages().unwrap() };
    print_info(&format!("Enumerated {} packages:", pkgs.len()));
    for (name, comment, caps, ver, rpcid, max_token) in &pkgs {
        print_info(&format!("  Package: {}, Comment: {}, Caps: 0x{:X}, Ver: {}, RPCID: {}, MaxToken: {}", name, comment, caps, ver, rpcid, max_token));
    }
    assert_eq!(pkgs.len(), 2);
    assert_eq!(pkgs[0].0, "GateKeeper");
    assert_eq!(pkgs[1].0, "NTLM");
    print_success("Security package enumeration verified successfully!");
}

/// Simulates standard GateKeeper client-server challenge-response.
fn test_gatekeeper_handshake(sspi: &SspiInterface) {
    print_header("1. GATEKEEPER SECURITY PROVIDER HANDSHAKE");

    let mut client_cred = CredHandle::default();
    let mut server_cred = CredHandle::default();

    unsafe {
        sspi.acquire_credentials_handle(None, "GateKeeper", 1, None, &mut client_cred).unwrap();
        sspi.acquire_credentials_handle(None, "GateKeeper", 2, None, &mut server_cred).unwrap();
    }

    print_info("Acquired handles. Commencing GateKeeper handshake.");

    let gk_id = b"GK_CLIENT_ID_TOK";
    let hostname = b"chat.msn.com";

    let client_input = vec![
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: gk_id.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
    ];
    let mut client_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx = CtxtHandle::default();
    let mut client_attr = 0u32;

    let res_c1 = unsafe {
        sspi.initialize_security_context(
            &client_cred,
            None,
            None,
            0,
            16,
            &client_input,
            &mut client_ctx,
            &mut client_output,
            &mut client_attr,
        ).unwrap()
    };

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let step1_token = client_output[0].bytes.clone();
    dump_buffer("Step 1 Client", &step1_token);

    let server_input = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: step1_token },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
    ];
    let mut server_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut server_ctx = CtxtHandle::default();
    let mut server_attr = 0u32;

    let res_s1 = unsafe {
        sspi.accept_security_context(
            &server_cred,
            None,
            &server_input,
            0,
            16,
            &mut server_ctx,
            &mut server_output,
            &mut server_attr,
        ).unwrap()
    };

    assert_eq!(res_s1, SspiError::ContinueNeeded);
    let step2_token = server_output[0].bytes.clone();
    dump_buffer("Step 1 Server", &step2_token);

    let client_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: step2_token },
    ];
    let mut client_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = unsafe {
        sspi.initialize_security_context(
            &client_cred,
            Some(&client_ctx),
            None,
            0,
            16,
            &client_input_2,
            &mut client_ctx_2,
            &mut client_output_2,
            &mut client_attr,
        ).unwrap()
    };

    assert_eq!(res_c2, SspiError::Ok);
    let step3_token = client_output_2[0].bytes.clone();
    dump_buffer("Step 2 Client", &step3_token);

    let server_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: step3_token },
    ];
    let mut server_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut server_ctx_2 = server_ctx;

    let res_s2 = unsafe {
        sspi.accept_security_context(
            &server_cred,
            Some(&server_ctx),
            &server_input_2,
            0,
            16,
            &mut server_ctx_2,
            &mut server_output_2,
            &mut server_attr,
        ).unwrap()
    };

    assert_eq!(res_s2, SspiError::Ok);

    // Query authenticated username from server security context
    let username = unsafe {
        sspi.query_context_attributes(&server_ctx_2, ircx_sspi::dll::SECPKG_ATTR_NAMES).unwrap()
    };
    print_info(&format!("Retrieved GateKeeper Username: {}", username));
    assert_eq!(username, "435F4B47494C4E45545F49445F544F4B");

    print_success("GateKeeper mutual handshake completed successfully!");

    unsafe {
        sspi.delete_security_context(&client_ctx_2).unwrap();
        sspi.delete_security_context(&server_ctx_2).unwrap();
        sspi.free_credentials_handle(&client_cred).unwrap();
        sspi.free_credentials_handle(&server_cred).unwrap();
    }
}

/// Simulates the legacy GateKeeper version 1 client-server challenge-response.
fn test_gatekeeper_legacy_v1_handshake(sspi: &SspiInterface) {
    print_header("1b. GATEKEEPER LEGACY VERSION 1 HANDSHAKE");

    let mut client_cred = CredHandle::default();
    let mut server_cred = CredHandle::default();

    unsafe {
        sspi.acquire_credentials_handle(None, "GateKeeper", 1, None, &mut client_cred).unwrap();
        sspi.acquire_credentials_handle(None, "GateKeeper", 2, None, &mut server_cred).unwrap();
    }

    print_info("Acquired handles. Commencing GateKeeper V1 legacy handshake.");

    let gk_id = b"GK_CLIENT_ID_TOK";
    let hostname = b"chat.msn.com";
    let client_ver_payload = 1u32.to_le_bytes();

    let client_input = vec![
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: gk_id.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: client_ver_payload.to_vec() },
    ];
    let mut client_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx = CtxtHandle::default();
    let mut client_attr = 0u32;

    let res_c1 = unsafe {
        sspi.initialize_security_context(
            &client_cred,
            None,
            None,
            0,
            16,
            &client_input,
            &mut client_ctx,
            &mut client_output,
            &mut client_attr,
        ).unwrap()
    };

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let step1_token = client_output[0].bytes.clone();
    dump_buffer("Step 1 Client V1", &step1_token);
    assert_eq!(step1_token.len(), 16);
    assert_eq!(u32::from_le_bytes(step1_token[8..12].try_into().unwrap()), 1);

    let server_input = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: step1_token },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: hostname.to_vec() },
        SecBuffer { buffer_type: SecBufferType::PkgParams, bytes: vec![1] }, // allow_older_versions = true
    ];
    let mut server_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut server_ctx = CtxtHandle::default();
    let mut server_attr = 0u32;

    let res_s1 = unsafe {
        sspi.accept_security_context(
            &server_cred,
            None,
            &server_input,
            0,
            16,
            &mut server_ctx,
            &mut server_output,
            &mut server_attr,
        ).unwrap()
    };

    assert_eq!(res_s1, SspiError::ContinueNeeded);
    let step2_token = server_output[0].bytes.clone();
    dump_buffer("Step 1 Server V1", &step2_token);
    assert_eq!(step2_token.len(), 24);
    assert_eq!(u32::from_le_bytes(step2_token[8..12].try_into().unwrap()), 1);

    let client_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: step2_token },
    ];
    let mut client_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = unsafe {
        sspi.initialize_security_context(
            &client_cred,
            Some(&client_ctx),
            None,
            0,
            16,
            &client_input_2,
            &mut client_ctx_2,
            &mut client_output_2,
            &mut client_attr,
        ).unwrap()
    };

    assert_eq!(res_c2, SspiError::Ok);
    let step3_token = client_output_2[0].bytes.clone();
    dump_buffer("Step 2 Client V1", &step3_token);
    assert_eq!(step3_token.len(), 32);

    let server_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: step3_token },
    ];
    let mut server_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut server_ctx_2 = server_ctx;

    let res_s2 = unsafe {
        sspi.accept_security_context(
            &server_cred,
            Some(&server_ctx),
            &server_input_2,
            0,
            16,
            &mut server_ctx_2,
            &mut server_output_2,
            &mut server_attr,
        ).unwrap()
    };

    assert_eq!(res_s2, SspiError::Ok);

    // Query authenticated username from server security context
    let username = unsafe {
        sspi.query_context_attributes(&server_ctx_2, ircx_sspi::dll::SECPKG_ATTR_NAMES).unwrap()
    };
    print_info(&format!("Retrieved GateKeeper V1 Username: {}", username));
    assert_eq!(username.len(), 32);
    assert_ne!(username, "00000000000000000000000000000000");
    assert!(username.chars().all(|c| c.is_ascii_hexdigit()));

    print_success("GateKeeper legacy V1 handshake completed successfully!");

    unsafe {
        sspi.delete_security_context(&client_ctx_2).unwrap();
        sspi.delete_security_context(&server_ctx_2).unwrap();
        sspi.free_credentials_handle(&client_cred).unwrap();
        sspi.free_credentials_handle(&server_cred).unwrap();
    }
}

/// Simulates standard NTLM challenge-response.
fn test_ntlm_handshake(sspi: &SspiInterface) {
    print_header("2. NTLM SECURITY PROVIDER HANDSHAKE");

    let mut client_cred = CredHandle::default();
    let mut server_cred = CredHandle::default();

    unsafe {
        sspi.acquire_credentials_handle(None, "NTLM", 1, None, &mut client_cred).unwrap();
        sspi.acquire_credentials_handle(None, "NTLM", 2, None, &mut server_cred).unwrap();
    }

    let mut client_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut client_ctx = CtxtHandle::default();
    let mut client_attr = 0u32;

    let res_c1 = unsafe {
        sspi.initialize_security_context(
            &client_cred,
            None,
            None,
            0,
            16,
            &[],
            &mut client_ctx,
            &mut client_output,
            &mut client_attr,
        ).unwrap()
    };

    assert_eq!(res_c1, SspiError::ContinueNeeded);
    let negotiate = client_output[0].bytes.clone();
    dump_buffer("Type 1 Negotiate", &negotiate);

    let server_input = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: negotiate },
    ];
    let mut server_output = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 256] },
    ];
    let mut server_ctx = CtxtHandle::default();
    let mut server_attr = 0u32;

    let res_s1 = unsafe {
        sspi.accept_security_context(
            &server_cred,
            None,
            &server_input,
            0,
            16,
            &mut server_ctx,
            &mut server_output,
            &mut server_attr,
        ).unwrap()
    };

    assert_eq!(res_s1, SspiError::ContinueNeeded);
    let challenge = server_output[0].bytes.clone();
    dump_buffer("Type 2 Challenge", &challenge);

    let client_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: challenge },
    ];
    let mut client_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 512] },
    ];
    let mut client_ctx_2 = client_ctx;

    let res_c2 = unsafe {
        sspi.initialize_security_context(
            &client_cred,
            Some(&client_ctx),
            None,
            0,
            16,
            &client_input_2,
            &mut client_ctx_2,
            &mut client_output_2,
            &mut client_attr,
        ).unwrap()
    };

    assert_eq!(res_c2, SspiError::Ok);
    let authenticate = client_output_2[0].bytes.clone();
    dump_buffer("Type 3 Authenticate", &authenticate);

    let server_input_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: authenticate },
    ];
    let mut server_output_2 = vec![
        SecBuffer { buffer_type: SecBufferType::Token, bytes: vec![0u8; 128] },
    ];
    let mut server_ctx_2 = server_ctx;

    let res_s2 = unsafe {
        sspi.accept_security_context(
            &server_cred,
            Some(&server_ctx),
            &server_input_2,
            0,
            16,
            &mut server_ctx_2,
            &mut server_output_2,
            &mut server_attr,
        ).unwrap()
    };

    assert_eq!(res_s2, SspiError::Ok);

    // Query authenticated username from server security context
    let username = unsafe {
        sspi.query_context_attributes(&server_ctx_2, ircx_sspi::dll::SECPKG_ATTR_NAMES).unwrap()
    };
    print_info(&format!("Retrieved NTLM Username: {}", username));
    assert_eq!(username, "TestUser");

    print_success("NTLM challenge-response handshake succeeded!");

    unsafe {
        sspi.delete_security_context(&client_ctx_2).unwrap();
        sspi.delete_security_context(&server_ctx_2).unwrap();
        sspi.free_credentials_handle(&client_cred).unwrap();
        sspi.free_credentials_handle(&server_cred).unwrap();
    }
}
