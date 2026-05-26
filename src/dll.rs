//! # MSN Chat SSPI DLL Wrapper
//!
//! Exposes a standard C/C++ compatible Windows Security Support Provider (SSP) DLL.
//! This implementation implements `InitSecurityInterfaceA` and `InitSecurityInterfaceW`
//! which return standard function tables, alongside direct C/C++ exports of standard
//! SSPI functions like `AcquireCredentialsHandleA`, `InitializeSecurityContextA`, etc.
//!
//! Using the standard system calling convention (`extern "system"`), this DLL is binary-compatible
//! with Windows SSPI clients, allowing dynamic routing of security contexts and credentials
//! to the high-fidelity Rust implementation.

#![allow(non_snake_case)]

use crate::types::SecurityProvider;
use std::sync::OnceLock;

/// Represents the standard `SecBuffer` struct layout in Windows (`sspi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecBuffer {
    /// Buffer size, in bytes.
    pub cb_buffer: u32,
    /// Buffer type (e.g. SECBUFFER_TOKEN = 2, SECBUFFER_PKG_PARAMS = 3).
    pub buffer_type: u32,
    /// Pointer to the allocated raw byte buffer in C/C++ memory.
    pub pv_buffer: *mut u8,
}

/// Represents the standard `SecBufferDesc` descriptor layout in Windows (`sspi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecBufferDesc {
    /// Version number of the descriptor (usually SECBUFFER_VERSION = 0).
    pub ul_version: u32,
    /// Number of buffers stored in the `p_buffers` array.
    pub c_buffers: u32,
    /// Pointer to the array of `SecBuffer` structs.
    pub p_buffers: *mut SecBuffer,
}

/// Helper to safely translate a pointer to a C-allocated `SecBufferDesc` into a Rust vector of `SecBuffer`s.
/// Returns an empty vector if the input pointer or its internal buffer array is null.
///
/// # Safety
/// The caller must ensure that the pointer `desc` is valid and points to a valid `SecBufferDesc` structure,
/// and that any nested buffer pointers and sizes are correctly allocated.
pub unsafe fn parse_c_buffers(desc: *const SecBufferDesc) -> Vec<crate::types::SecBuffer> {
    if desc.is_null() {
        return Vec::new();
    }
    // SAFETY: We checked that `desc` is not null. The caller guarantees the validity of the pointer.
    let desc_ref = unsafe { &*desc };
    if desc_ref.p_buffers.is_null() || desc_ref.c_buffers == 0 {
        return Vec::new();
    }
    let mut buffers = Vec::new();
    for i in 0..desc_ref.c_buffers {
        // SAFETY: The caller guarantees `p_buffers` points to an array of size at least `c_buffers`.
        let c_buf = unsafe { &*desc_ref.p_buffers.add(i as usize) };
        let bytes = if c_buf.pv_buffer.is_null() || c_buf.cb_buffer == 0 {
            Vec::new()
        } else {
            // SAFETY: The caller guarantees that `pv_buffer` points to valid memory of size `cb_buffer`.
            unsafe {
                std::slice::from_raw_parts(c_buf.pv_buffer, c_buf.cb_buffer as usize).to_vec()
            }
        };
        buffers.push(crate::types::SecBuffer {
            buffer_type: crate::types::SecBufferType::from(c_buf.buffer_type),
            bytes,
        });
    }
    buffers
}

/// Helper to copy Rust token outcomes back to caller-allocated C-style `SecBufferDesc` segments.
/// Matches buffer types (e.g., Token, PkgParams) to ensure proper output data assignment.
///
/// # Safety
/// The caller must ensure `desc` is a valid pointer to an output descriptor and holds sufficient memory capacity.
pub unsafe fn write_back_c_buffers(
    desc: *mut SecBufferDesc,
    rust_buffers: &[crate::types::SecBuffer],
) {
    if desc.is_null() {
        return;
    }
    // SAFETY: We checked that `desc` is not null. The caller guarantees the validity of the pointer.
    let desc_ref = unsafe { &mut *desc };
    if desc_ref.p_buffers.is_null() || desc_ref.c_buffers == 0 {
        return;
    }
    for i in 0..desc_ref.c_buffers {
        // SAFETY: The caller guarantees `p_buffers` points to an array of size at least `c_buffers`.
        let c_buf = unsafe { &mut *desc_ref.p_buffers.add(i as usize) };
        let rust_type = crate::types::SecBufferType::from(c_buf.buffer_type);
        if let Some(r_buf) = rust_buffers.iter().find(|b| b.buffer_type == rust_type) {
            let len = r_buf.bytes.len().min(c_buf.cb_buffer as usize);
            if len > 0 && !c_buf.pv_buffer.is_null() {
                // SAFETY: Pointers are valid and non-overlapping.
                unsafe {
                    std::ptr::copy_nonoverlapping(r_buf.bytes.as_ptr(), c_buf.pv_buffer, len);
                }
            }
            c_buf.cb_buffer = len as u32;
        }
    }
}

/// Registry of global security provider instances loaded inside the DLL process.
/// Using static initialization ensures their internal contexts remain valid across multiple SSPI transitions.
struct Providers {
    gatekeeper: crate::GateKeeperSecurityProvider,
    ntlm: crate::NtlmSecurityProvider,
}

/// Retrieves a static reference to the global providers registry.
fn get_providers() -> &'static Providers {
    static PROVIDERS: OnceLock<Providers> = OnceLock::new();
    PROVIDERS.get_or_init(|| {
        let gatekeeper = crate::GateKeeperSecurityProvider::new();
        let ntlm = crate::NtlmSecurityProvider::new();

        let _ = gatekeeper.initialize();
        let _ = ntlm.initialize();

        Providers { gatekeeper, ntlm }
    })
}

/// Helper routing an incoming `CredHandle` to the matching global security provider based on `dw_upper`.
fn get_provider_by_cred(
    handle: &crate::types::CredHandle,
) -> Option<&'static dyn crate::types::SecurityProvider> {
    let p = get_providers();
    match handle.dw_upper {
        0x8888 => Some(&p.gatekeeper),
        0x6666 => Some(&p.ntlm),
        _ => None,
    }
}

/// Helper routing an incoming `CtxtHandle` to the matching global security provider based on `dw_upper`.
fn get_provider_by_ctxt(
    handle: &crate::types::CtxtHandle,
) -> Option<&'static dyn crate::types::SecurityProvider> {
    let p = get_providers();
    match handle.dw_upper {
        0x1000 | 0x2000 => Some(&p.gatekeeper),
        0x5000 | 0x6000 => Some(&p.ntlm),
        _ => None,
    }
}

/// Maps standard package names string queries case-insensitively to the correct active provider instance.
fn get_provider_by_name(package: &str) -> Option<&'static dyn crate::types::SecurityProvider> {
    let p = get_providers();
    let name_lower = package.to_ascii_lowercase();
    match name_lower.as_str() {
        "gatekeeper" => Some(&p.gatekeeper),
        "ntlm" => Some(&p.ntlm),
        _ => None,
    }
}

// ============================================================================
// Direct SSPI Exports matching standard Windows signatures
// ============================================================================

/// Acquires a handle to pre-existing credentials for a specific security package (ANSI version).
///
/// # Safety
/// Standard C-style pointers must be valid or null; bounds are verified before usage.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AcquireCredentialsHandleA(
    _pszPrincipal: *const i8,
    pszPackage: *const i8,
    fCredentialUse: u32,
    _pvLogonID: *const std::ffi::c_void,
    pAuthData: *const std::ffi::c_void,
    _pGetKeyFn: *const std::ffi::c_void,
    _pvGetKeyArgument: *const std::ffi::c_void,
    phCredential: *mut crate::types::CredHandle,
    _ptsExpiry: *mut u64,
) -> i32 {
    if pszPackage.is_null() || phCredential.is_null() {
        return crate::types::SspiError::UnknownCredentials.to_raw();
    }
    // SAFETY: We verified `pszPackage` is not null. The caller guarantees it points to a valid null-terminated string.
    let pkg_name = match unsafe { std::ffi::CStr::from_ptr(pszPackage) }.to_str() {
        Ok(s) => s,
        Err(_) => return crate::types::SspiError::UnknownCredentials.to_raw(),
    };
    let provider = match get_provider_by_name(pkg_name) {
        Some(p) => p,
        None => return crate::types::SspiError::NotSupported.to_raw(),
    };

    // Convert auth data pointer if supplied
    let auth_data = if pAuthData.is_null() { None } else { None };

    let mut cred = crate::types::CredHandle::default();
    match provider.acquire_credentials_handle(None, pkg_name, fCredentialUse, auth_data, &mut cred)
    {
        Ok(_) => {
            // SAFETY: We verified `phCredential` is not null and is writable.
            unsafe {
                *phCredential = cred;
            }
            crate::types::SspiError::Ok.to_raw()
        }
        Err(e) => e.to_raw(),
    }
}

/// Acquires a handle to pre-existing credentials for a specific security package (Wide/Unicode version).
///
/// # Safety
/// Standard C-style wide-pointers must be valid; null checks are strictly enforced.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AcquireCredentialsHandleW(
    _pszPrincipal: *const u16,
    pszPackage: *const u16,
    fCredentialUse: u32,
    _pvLogonID: *const std::ffi::c_void,
    _pAuthData: *const std::ffi::c_void,
    _pGetKeyFn: *const std::ffi::c_void,
    _pvGetKeyArgument: *const std::ffi::c_void,
    phCredential: *mut crate::types::CredHandle,
    _ptsExpiry: *mut u64,
) -> i32 {
    if pszPackage.is_null() || phCredential.is_null() {
        return crate::types::SspiError::UnknownCredentials.to_raw();
    }
    let mut len = 0;
    // SAFETY: We checked `pszPackage` is not null. The caller guarantees a valid null-terminated broad char array.
    unsafe {
        while *pszPackage.add(len) != 0 {
            len += 1;
        }
    }
    // SAFETY: The memory is valid for reading the full length.
    let slice = unsafe { std::slice::from_raw_parts(pszPackage, len) };
    let pkg_name = String::from_utf16_lossy(slice);
    let provider = match get_provider_by_name(&pkg_name) {
        Some(p) => p,
        None => return crate::types::SspiError::NotSupported.to_raw(),
    };

    let mut cred = crate::types::CredHandle::default();
    match provider.acquire_credentials_handle(None, &pkg_name, fCredentialUse, None, &mut cred) {
        Ok(_) => {
            // SAFETY: `phCredential` is valid and writable.
            unsafe {
                *phCredential = cred;
            }
            crate::types::SspiError::Ok.to_raw()
        }
        Err(e) => e.to_raw(),
    }
}

/// Frees an acquired credentials handle.
///
/// # Safety
/// Validates pointer addresses and routes context correctly.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn FreeCredentialsHandle(
    phCredential: *const crate::types::CredHandle,
) -> i32 {
    if phCredential.is_null() {
        return crate::types::SspiError::UnknownCredentials.to_raw();
    }
    // SAFETY: Checked not null. Pointer is valid for read.
    let cred = unsafe { &*phCredential };
    let provider = match get_provider_by_cred(cred) {
        Some(p) => p,
        None => return crate::types::SspiError::UnknownCredentials.to_raw(),
    };
    match provider.free_credentials_handle(cred) {
        Ok(_) => crate::types::SspiError::Ok.to_raw(),
        Err(e) => e.to_raw(),
    }
}

/// Drives standard client-side security context establishment (ANSI version).
///
/// # Safety
/// Pointers must represent valid memory bounds. Input/output buffer types are fully verified.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InitializeSecurityContextA(
    phCredential: *const crate::types::CredHandle,
    phContext: *const crate::types::CtxtHandle,
    pszTargetName: *const i8,
    fContextReq: u32,
    _Reserved1: u32,
    TargetDataRep: u32,
    pInput: *const SecBufferDesc,
    _Reserved2: u32,
    phNewContext: *mut crate::types::CtxtHandle,
    pOutput: *mut SecBufferDesc,
    pfContextAttr: *mut u32,
    _ptsExpiry: *mut u64,
) -> i32 {
    if phCredential.is_null() || phNewContext.is_null() || pfContextAttr.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    // SAFETY: Checked and resolved properly under safe block wrappers.
    let context_ref = if phContext.is_null() {
        None
    } else {
        Some(unsafe { &*phContext })
    };
    let provider = if let Some(ctx) = context_ref {
        match get_provider_by_ctxt(ctx) {
            Some(p) => p,
            None => return crate::types::SspiError::InvalidHandle.to_raw(),
        }
    } else {
        // SAFETY: Checked pointer validity for reading.
        match get_provider_by_cred(unsafe { &*phCredential }) {
            Some(p) => p,
            None => return crate::types::SspiError::UnknownCredentials.to_raw(),
        }
    };

    let target_name = if pszTargetName.is_null() {
        None
    } else {
        // SAFETY: The target name string is null-terminated.
        unsafe { std::ffi::CStr::from_ptr(pszTargetName) }
            .to_str()
            .ok()
    };

    // SAFETY: Pointers are validated.
    let input_bufs = unsafe { parse_c_buffers(pInput) };
    let mut output_bufs = unsafe { parse_c_buffers(pOutput) };

    let mut new_ctx = if phContext.is_null() {
        crate::types::CtxtHandle::default()
    } else {
        unsafe { *phContext }
    };
    let mut attr = 0;

    // SAFETY: Credentials pointer is safe to read.
    match provider.initialize_security_context(
        unsafe { &*phCredential },
        context_ref,
        target_name,
        fContextReq,
        TargetDataRep,
        &input_bufs,
        &mut new_ctx,
        &mut output_bufs,
        &mut attr,
    ) {
        Ok(status) => {
            // SAFETY: Output pointers are writable.
            unsafe {
                *phNewContext = new_ctx;
                *pfContextAttr = attr;
                write_back_c_buffers(pOutput, &output_bufs);
            }
            status.to_raw()
        }
        Err(e) => e.to_raw(),
    }
}

/// Drives standard client-side security context establishment (Wide/Unicode version).
///
/// # Safety
/// Pointers must represent valid memory bounds. Input/output buffer types are fully verified.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InitializeSecurityContextW(
    phCredential: *const crate::types::CredHandle,
    phContext: *const crate::types::CtxtHandle,
    pszTargetName: *const u16,
    fContextReq: u32,
    _Reserved1: u32,
    TargetDataRep: u32,
    pInput: *const SecBufferDesc,
    _Reserved2: u32,
    phNewContext: *mut crate::types::CtxtHandle,
    pOutput: *mut SecBufferDesc,
    pfContextAttr: *mut u32,
    _ptsExpiry: *mut u64,
) -> i32 {
    if phCredential.is_null() || phNewContext.is_null() || pfContextAttr.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    // SAFETY: Checked pointer parameters.
    let context_ref = if phContext.is_null() {
        None
    } else {
        Some(unsafe { &*phContext })
    };
    let provider = if let Some(ctx) = context_ref {
        match get_provider_by_ctxt(ctx) {
            Some(p) => p,
            None => return crate::types::SspiError::InvalidHandle.to_raw(),
        }
    } else {
        // SAFETY: Checked pointer bounds.
        match get_provider_by_cred(unsafe { &*phCredential }) {
            Some(p) => p,
            None => return crate::types::SspiError::UnknownCredentials.to_raw(),
        }
    };

    let target_name_str;
    let target_name = if pszTargetName.is_null() {
        None
    } else {
        let mut len = 0;
        // SAFETY: The wide string must be null terminated.
        unsafe {
            while *pszTargetName.add(len) != 0 {
                len += 1;
            }
        }
        // SAFETY: Length bounds verified.
        let slice = unsafe { std::slice::from_raw_parts(pszTargetName, len) };
        target_name_str = String::from_utf16_lossy(slice);
        Some(target_name_str.as_str())
    };

    // SAFETY: Buffer descriptions parse.
    let input_bufs = unsafe { parse_c_buffers(pInput) };
    let mut output_bufs = unsafe { parse_c_buffers(pOutput) };

    let mut new_ctx = if phContext.is_null() {
        crate::types::CtxtHandle::default()
    } else {
        unsafe { *phContext }
    };
    let mut attr = 0;

    // SAFETY: Pointer arguments are safely accessed.
    match provider.initialize_security_context(
        unsafe { &*phCredential },
        context_ref,
        target_name,
        fContextReq,
        TargetDataRep,
        &input_bufs,
        &mut new_ctx,
        &mut output_bufs,
        &mut attr,
    ) {
        Ok(status) => {
            // SAFETY: Output locations are writable.
            unsafe {
                *phNewContext = new_ctx;
                *pfContextAttr = attr;
                write_back_c_buffers(pOutput, &output_bufs);
            }
            status.to_raw()
        }
        Err(e) => e.to_raw(),
    }
}

/// Drives standard server-side security context acceptance.
///
/// # Safety
/// Pointers must represent valid memory bounds. Input/output buffer types are fully verified.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn AcceptSecurityContext(
    phCredential: *const crate::types::CredHandle,
    phContext: *const crate::types::CtxtHandle,
    pInput: *const SecBufferDesc,
    fContextReq: u32,
    TargetDataRep: u32,
    phNewContext: *mut crate::types::CtxtHandle,
    pOutput: *mut SecBufferDesc,
    pfContextAttr: *mut u32,
    _ptsExpiry: *mut u64,
) -> i32 {
    if phCredential.is_null() || phNewContext.is_null() || pfContextAttr.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    // SAFETY: Validated handle pointer boundaries.
    let context_ref = if phContext.is_null() {
        None
    } else {
        Some(unsafe { &*phContext })
    };
    let provider = if let Some(ctx) = context_ref {
        match get_provider_by_ctxt(ctx) {
            Some(p) => p,
            None => return crate::types::SspiError::InvalidHandle.to_raw(),
        }
    } else {
        // SAFETY: Pointer is valid for read.
        match get_provider_by_cred(unsafe { &*phCredential }) {
            Some(p) => p,
            None => return crate::types::SspiError::UnknownCredentials.to_raw(),
        }
    };

    // SAFETY: Buffer pointer parsing.
    let input_bufs = unsafe { parse_c_buffers(pInput) };
    let mut output_bufs = unsafe { parse_c_buffers(pOutput) };

    let mut new_ctx = if phContext.is_null() {
        crate::types::CtxtHandle::default()
    } else {
        unsafe { *phContext }
    };
    let mut attr = 0;

    // SAFETY: Standard trait invocation with validated parameters.
    match provider.accept_security_context(
        unsafe { &*phCredential },
        context_ref,
        &input_bufs,
        fContextReq,
        TargetDataRep,
        &mut new_ctx,
        &mut output_bufs,
        &mut attr,
    ) {
        Ok(status) => {
            // SAFETY: Output boundaries are writable.
            unsafe {
                *phNewContext = new_ctx;
                *pfContextAttr = attr;
                write_back_c_buffers(pOutput, &output_bufs);
            }
            status.to_raw()
        }
        Err(e) => e.to_raw(),
    }
}

/// Deletes an established security context.
///
/// # Safety
/// Validates pointer addresses and deletes the context mapping correctly.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DeleteSecurityContext(
    phContext: *const crate::types::CtxtHandle,
) -> i32 {
    if phContext.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }
    // SAFETY: Checked pointer not null.
    let ctx = unsafe { &*phContext };
    let provider = match get_provider_by_ctxt(ctx) {
        Some(p) => p,
        None => return crate::types::SspiError::InvalidHandle.to_raw(),
    };
    match provider.delete_security_context(ctx) {
        Ok(_) => crate::types::SspiError::Ok.to_raw(),
        Err(e) => e.to_raw(),
    }
}

/// Stub handler returning `SEC_E_UNSUPPORTED` for unimplemented SSPI interfaces.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn UnsupportedStub() -> i32 {
    crate::types::SspiError::NotSupported.to_raw()
}

/// Standard SSPI constant for querying username associated with a context.
pub const SECPKG_ATTR_NAMES: u32 = 1;

/// Represents standard `SecPkgContext_NamesA` struct layout in Windows (`sspi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecPkgContext_NamesA {
    pub sUserName: *mut i8,
}

/// Represents standard `SecPkgContext_NamesW` struct layout in Windows (`sspi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecPkgContext_NamesW {
    pub sUserName: *mut u16,
}

/// Safely allocates an SSPI buffer with a layout-prefixed size.
///
/// # Safety
/// Standard Rust allocator is used. Total size allocated is `bytes_needed + 8`.
pub unsafe fn allocate_sspi_buffer(bytes_needed: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(bytes_needed + 8, 8).unwrap();
    // SAFETY: Layout has non-zero size.
    let raw = unsafe { std::alloc::alloc(layout) };
    if raw.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: Raw pointer is valid and properly aligned.
    unsafe {
        *(raw as *mut u64) = (bytes_needed + 8) as u64;
        raw.add(8)
    }
}

/// Safely deallocates a layout-prefixed SSPI buffer.
///
/// # Safety
/// Reconstructs the allocation layout from the prefixed size.
pub unsafe fn free_sspi_buffer(ptr: *mut std::ffi::c_void) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: Pointer is valid, we offset it by -8 to retrieve the header.
    unsafe {
        let raw = (ptr as *mut u8).sub(8);
        let size = *(raw as *mut u64) as usize;
        let layout = std::alloc::Layout::from_size_align(size, 8).unwrap();
        std::alloc::dealloc(raw, layout);
    }
}

/// Frees an SSPI context buffer allocated by the security package.
///
/// # Safety
/// Deallocates layout-prefixed buffers safely.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn FreeContextBuffer(pv: *mut std::ffi::c_void) -> i32 {
    if pv.is_null() {
        return crate::types::SspiError::Ok.to_raw();
    }
    // SAFETY: pv points to valid allocated SSPI buffer.
    unsafe {
        free_sspi_buffer(pv);
    }
    crate::types::SspiError::Ok.to_raw()
}

/// Helper to format a GateKeeper 16-byte raw ID.
/// If the ID consists of printable ASCII characters, it is returned directly as a string.
/// Otherwise, it is formatted as a 32-character uppercase hex string using the
/// ActiveX GUID byte-swapping formula.
pub fn format_gatekeeper_id(bytes: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Queries attributes of a security context (ANSI version).
///
/// # Safety
/// phContext and pBuffer must point to valid memory segments.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryContextAttributesA(
    phContext: *const crate::types::CtxtHandle,
    ulAttribute: u32,
    pBuffer: *mut std::ffi::c_void,
) -> i32 {
    if phContext.is_null() || pBuffer.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    // SAFETY: Checked pointer not null.
    let ctx = unsafe { &*phContext };

    if ulAttribute == SECPKG_ATTR_NAMES {
        let providers = get_providers();
        let username = match ctx.dw_upper {
            0x1000 | 0x2000 => {
                let sessions = providers.gatekeeper.sessions.lock().unwrap();
                if let Some(s) = sessions.get(ctx) {
                    Some(format_gatekeeper_id(&s.gatekeeper_id))
                } else {
                    None
                }
            }
            0x5000 | 0x6000 => {
                let sessions = providers.ntlm.sessions.lock().unwrap();
                if let Some(s) = sessions.get(ctx) {
                    match (&s.authenticated_domain, &s.authenticated_username) {
                        (Some(domain), Some(user)) if !domain.is_empty() => {
                            Some(format!("{}\\{}", domain, user))
                        }
                        (_, Some(user)) => Some(user.clone()),
                        _ => Some("user".to_string()),
                    }
                } else {
                    Some("user".to_string())
                }
            }
            _ => None,
        };

        if let Some(uname) = username {
            let name_bytes = uname.as_bytes();
            let len = name_bytes.len() + 1;
            // SAFETY: Allocate buffer for ANSI string.
            let ptr = unsafe { allocate_sspi_buffer(len) };
            if ptr.is_null() {
                return crate::types::SspiError::InvalidToken.to_raw();
            }
            // SAFETY: Write bytes and null-terminator.
            unsafe {
                std::ptr::copy_nonoverlapping(name_bytes.as_ptr(), ptr, name_bytes.len());
                *ptr.add(name_bytes.len()) = 0;

                let names_struct = pBuffer as *mut SecPkgContext_NamesA;
                (*names_struct).sUserName = ptr as *mut i8;
            }
            return crate::types::SspiError::Ok.to_raw();
        } else {
            return crate::types::SspiError::InvalidHandle.to_raw();
        }
    }

    crate::types::SspiError::NotSupported.to_raw()
}

/// Queries attributes of a security context (Unicode/Wide version).
///
/// # Safety
/// phContext and pBuffer must point to valid memory segments.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn QueryContextAttributesW(
    phContext: *const crate::types::CtxtHandle,
    ulAttribute: u32,
    pBuffer: *mut std::ffi::c_void,
) -> i32 {
    if phContext.is_null() || pBuffer.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    // SAFETY: Checked pointer not null.
    let ctx = unsafe { &*phContext };

    if ulAttribute == SECPKG_ATTR_NAMES {
        let providers = get_providers();
        let username = match ctx.dw_upper {
            0x1000 | 0x2000 => {
                let sessions = providers.gatekeeper.sessions.lock().unwrap();
                if let Some(s) = sessions.get(ctx) {
                    Some(format_gatekeeper_id(&s.gatekeeper_id))
                } else {
                    None
                }
            }
            0x5000 | 0x6000 => {
                let sessions = providers.ntlm.sessions.lock().unwrap();
                if let Some(s) = sessions.get(ctx) {
                    match (&s.authenticated_domain, &s.authenticated_username) {
                        (Some(domain), Some(user)) if !domain.is_empty() => {
                            Some(format!("{}\\{}", domain, user))
                        }
                        (_, Some(user)) => Some(user.clone()),
                        _ => Some("user".to_string()),
                    }
                } else {
                    Some("user".to_string())
                }
            }
            _ => None,
        };

        if let Some(uname) = username {
            let wide_chars: Vec<u16> = uname.encode_utf16().chain(std::iter::once(0)).collect();
            let len_bytes = wide_chars.len() * 2;
            // SAFETY: Allocate buffer for wide string.
            let ptr = unsafe { allocate_sspi_buffer(len_bytes) };
            if ptr.is_null() {
                return crate::types::SspiError::InvalidToken.to_raw();
            }
            // SAFETY: Copy wide string content.
            unsafe {
                std::ptr::copy_nonoverlapping(wide_chars.as_ptr() as *const u8, ptr, len_bytes);

                let names_struct = pBuffer as *mut SecPkgContext_NamesW;
                (*names_struct).sUserName = ptr as *mut u16;
            }
            return crate::types::SspiError::Ok.to_raw();
        } else {
            return crate::types::SspiError::InvalidHandle.to_raw();
        }
    }

    crate::types::SspiError::NotSupported.to_raw()
}

/// Represents standard `SecPkgInfoA` struct layout in Windows (`sspi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecPkgInfoA {
    pub f_capabilities: u32,
    pub w_version: u16,
    pub w_rpcid: u16,
    pub cb_max_token: u32,
    pub name: *mut i8,
    pub comment: *mut i8,
}

/// Represents standard `SecPkgInfoW` struct layout in Windows (`sspi.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SecPkgInfoW {
    pub f_capabilities: u32,
    pub w_version: u16,
    pub w_rpcid: u16,
    pub cb_max_token: u32,
    pub name: *mut u16,
    pub comment: *mut u16,
}

/// Lists all supported security packages in ANSI format.
///
/// # Safety
/// pcPackages and ppPackageInfo must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EnumerateSecurityPackagesA(
    pcPackages: *mut u32,
    ppPackageInfo: *mut *mut SecPkgInfoA,
) -> i32 {
    if pcPackages.is_null() || ppPackageInfo.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    let pkgs = [
        (
            "GateKeeper",
            "GateKeeper Security Package",
            0x34u32,
            1u16,
            0xFFFFu16,
            0x40u32,
        ),
        (
            "NTLM",
            "NTLM Security Package",
            0x14u32,
            1u16,
            10u16,
            2888u32,
        ),
    ];

    let count = pkgs.len();
    let struct_size = count * std::mem::size_of::<SecPkgInfoA>();
    let mut total_string_size = 0;
    for &(name, comment, _, _, _, _) in &pkgs {
        total_string_size += name.len() + 1;
        total_string_size += comment.len() + 1;
    }

    let total_bytes = struct_size + total_string_size;
    let ptr = unsafe { allocate_sspi_buffer(total_bytes) };
    if ptr.is_null() {
        return crate::types::SspiError::InvalidToken.to_raw();
    }

    let info_array = ptr as *mut SecPkgInfoA;
    let mut string_offset = struct_size;

    for (i, &(name, comment, caps, ver, rpcid, max_token)) in pkgs.iter().enumerate() {
        let name_ptr = unsafe { ptr.add(string_offset) as *mut i8 };
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), name_ptr as *mut u8, name.len());
            *name_ptr.add(name.len()) = 0;
        }
        string_offset += name.len() + 1;

        let comment_ptr = unsafe { ptr.add(string_offset) as *mut i8 };
        unsafe {
            std::ptr::copy_nonoverlapping(comment.as_ptr(), comment_ptr as *mut u8, comment.len());
            *comment_ptr.add(comment.len()) = 0;
        }
        string_offset += comment.len() + 1;

        unsafe {
            *info_array.add(i) = SecPkgInfoA {
                f_capabilities: caps,
                w_version: ver,
                w_rpcid: rpcid,
                cb_max_token: max_token,
                name: name_ptr,
                comment: comment_ptr,
            };
        }
    }

    unsafe {
        *pcPackages = count as u32;
        *ppPackageInfo = info_array;
    }

    crate::types::SspiError::Ok.to_raw()
}

/// Lists all supported security packages in Unicode format.
///
/// # Safety
/// pcPackages and ppPackageInfo must be valid writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn EnumerateSecurityPackagesW(
    pcPackages: *mut u32,
    ppPackageInfo: *mut *mut SecPkgInfoW,
) -> i32 {
    if pcPackages.is_null() || ppPackageInfo.is_null() {
        return crate::types::SspiError::InvalidHandle.to_raw();
    }

    let pkgs = [
        (
            "GateKeeper",
            "GateKeeper Security Package",
            0x34u32,
            1u16,
            0xFFFFu16,
            0x40u32,
        ),
        (
            "NTLM",
            "Microsoft NTLM Security Provider",
            0x14u32,
            1u16,
            10u16,
            2888u32,
        ),
    ];

    let count = pkgs.len();
    let struct_size = count * std::mem::size_of::<SecPkgInfoW>();
    let mut total_string_size = 0;
    for &(name, comment, _, _, _, _) in &pkgs {
        total_string_size += (name.chars().count() + 1) * 2;
        total_string_size += (comment.chars().count() + 1) * 2;
    }

    let total_bytes = struct_size + total_string_size;
    let ptr = unsafe { allocate_sspi_buffer(total_bytes) };
    if ptr.is_null() {
        return crate::types::SspiError::InvalidToken.to_raw();
    }

    let info_array = ptr as *mut SecPkgInfoW;
    let mut string_offset = struct_size;

    for (i, &(name, comment, caps, ver, rpcid, max_token)) in pkgs.iter().enumerate() {
        let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let name_ptr = unsafe { ptr.add(string_offset) as *mut u16 };
        unsafe {
            std::ptr::copy_nonoverlapping(name_wide.as_ptr(), name_ptr, name_wide.len());
        }
        string_offset += name_wide.len() * 2;

        let comment_wide: Vec<u16> = comment.encode_utf16().chain(std::iter::once(0)).collect();
        let comment_ptr = unsafe { ptr.add(string_offset) as *mut u16 };
        unsafe {
            std::ptr::copy_nonoverlapping(comment_wide.as_ptr(), comment_ptr, comment_wide.len());
        }
        string_offset += comment_wide.len() * 2;

        unsafe {
            *info_array.add(i) = SecPkgInfoW {
                f_capabilities: caps,
                w_version: ver,
                w_rpcid: rpcid,
                cb_max_token: max_token,
                name: name_ptr,
                comment: comment_ptr,
            };
        }
    }

    unsafe {
        *pcPackages = count as u32;
        *ppPackageInfo = info_array;
    }

    crate::types::SspiError::Ok.to_raw()
}

// ============================================================================
// Security Support Provider Interface (SSPI) Table structs
// ============================================================================

/// Represents standard `SecurityFunctionTableA` struct layout (`sspi.h`).
#[repr(C)]
pub struct SecurityFunctionTableA {
    pub dw_version: u32,
    pub enumerate_security_packages_a: *const std::ffi::c_void,
    pub query_credentials_attributes_a: *const std::ffi::c_void,
    pub acquire_credentials_handle_a: *const std::ffi::c_void,
    pub free_credentials_handle: *const std::ffi::c_void,
    pub reserved2: *const std::ffi::c_void,
    pub initialize_security_context_a: *const std::ffi::c_void,
    pub accept_security_context: *const std::ffi::c_void,
    pub complete_auth_token: *const std::ffi::c_void,
    pub delete_security_context: *const std::ffi::c_void,
    pub apply_control_token: *const std::ffi::c_void,
    pub query_context_attributes_a: *const std::ffi::c_void,
    pub impersonate_security_context: *const std::ffi::c_void,
    pub revert_security_context: *const std::ffi::c_void,
    pub make_signature: *const std::ffi::c_void,
    pub verify_signature: *const std::ffi::c_void,
    pub free_context_buffer: *const std::ffi::c_void,
    pub query_security_package_info_a: *const std::ffi::c_void,
    pub reserved3: *const std::ffi::c_void,
    pub reserved4: *const std::ffi::c_void,
    pub export_security_context: *const std::ffi::c_void,
    pub import_security_context_a: *const std::ffi::c_void,
    pub query_security_context_token: *const std::ffi::c_void,
    pub support_security_interface_a: *const std::ffi::c_void,
    pub decrypt_message: *const std::ffi::c_void,
    pub encrypt_message: *const std::ffi::c_void,
}

// SAFETY: Struct is pure static data table representation, and pointer values are completely immutable and shared safely.
unsafe impl Sync for SecurityFunctionTableA {}

/// Represents standard `SecurityFunctionTableW` struct layout (`sspi.h`).
#[repr(C)]
pub struct SecurityFunctionTableW {
    pub dw_version: u32,
    pub enumerate_security_packages_w: *const std::ffi::c_void,
    pub query_credentials_attributes_w: *const std::ffi::c_void,
    pub acquire_credentials_handle_w: *const std::ffi::c_void,
    pub free_credentials_handle: *const std::ffi::c_void,
    pub reserved2: *const std::ffi::c_void,
    pub initialize_security_context_w: *const std::ffi::c_void,
    pub accept_security_context: *const std::ffi::c_void,
    pub complete_auth_token: *const std::ffi::c_void,
    pub delete_security_context: *const std::ffi::c_void,
    pub apply_control_token: *const std::ffi::c_void,
    pub query_context_attributes_w: *const std::ffi::c_void,
    pub impersonate_security_context: *const std::ffi::c_void,
    pub revert_security_context: *const std::ffi::c_void,
    pub make_signature: *const std::ffi::c_void,
    pub verify_signature: *const std::ffi::c_void,
    pub free_context_buffer: *const std::ffi::c_void,
    pub query_security_package_info_w: *const std::ffi::c_void,
    pub reserved3: *const std::ffi::c_void,
    pub reserved4: *const std::ffi::c_void,
    pub export_security_context: *const std::ffi::c_void,
    pub import_security_context_w: *const std::ffi::c_void,
    pub query_security_context_token: *const std::ffi::c_void,
    pub support_security_interface_w: *const std::ffi::c_void,
    pub decrypt_message: *const std::ffi::c_void,
    pub encrypt_message: *const std::ffi::c_void,
}

// SAFETY: Struct is pure static data table representation, and pointer values are completely immutable and shared safely.
unsafe impl Sync for SecurityFunctionTableW {}

// Global Static tables loaded during dynamic binding link
static FUNCTION_TABLE_A: SecurityFunctionTableA = SecurityFunctionTableA {
    dw_version: 1,
    enumerate_security_packages_a: EnumerateSecurityPackagesA as *const std::ffi::c_void,
    query_credentials_attributes_a: UnsupportedStub as *const std::ffi::c_void,
    acquire_credentials_handle_a: AcquireCredentialsHandleA as *const std::ffi::c_void,
    free_credentials_handle: FreeCredentialsHandle as *const std::ffi::c_void,
    reserved2: std::ptr::null(),
    initialize_security_context_a: InitializeSecurityContextA as *const std::ffi::c_void,
    accept_security_context: AcceptSecurityContext as *const std::ffi::c_void,
    complete_auth_token: UnsupportedStub as *const std::ffi::c_void,
    delete_security_context: DeleteSecurityContext as *const std::ffi::c_void,
    apply_control_token: UnsupportedStub as *const std::ffi::c_void,
    query_context_attributes_a: QueryContextAttributesA as *const std::ffi::c_void,
    impersonate_security_context: UnsupportedStub as *const std::ffi::c_void,
    revert_security_context: UnsupportedStub as *const std::ffi::c_void,
    make_signature: UnsupportedStub as *const std::ffi::c_void,
    verify_signature: UnsupportedStub as *const std::ffi::c_void,
    free_context_buffer: FreeContextBuffer as *const std::ffi::c_void,
    query_security_package_info_a: UnsupportedStub as *const std::ffi::c_void,
    reserved3: std::ptr::null(),
    reserved4: std::ptr::null(),
    export_security_context: UnsupportedStub as *const std::ffi::c_void,
    import_security_context_a: UnsupportedStub as *const std::ffi::c_void,
    query_security_context_token: UnsupportedStub as *const std::ffi::c_void,
    support_security_interface_a: UnsupportedStub as *const std::ffi::c_void,
    decrypt_message: UnsupportedStub as *const std::ffi::c_void,
    encrypt_message: UnsupportedStub as *const std::ffi::c_void,
};

static FUNCTION_TABLE_W: SecurityFunctionTableW = SecurityFunctionTableW {
    dw_version: 1,
    enumerate_security_packages_w: EnumerateSecurityPackagesW as *const std::ffi::c_void,
    query_credentials_attributes_w: UnsupportedStub as *const std::ffi::c_void,
    acquire_credentials_handle_w: AcquireCredentialsHandleW as *const std::ffi::c_void,
    free_credentials_handle: FreeCredentialsHandle as *const std::ffi::c_void,
    reserved2: std::ptr::null(),
    initialize_security_context_w: InitializeSecurityContextW as *const std::ffi::c_void,
    accept_security_context: AcceptSecurityContext as *const std::ffi::c_void,
    complete_auth_token: UnsupportedStub as *const std::ffi::c_void,
    delete_security_context: DeleteSecurityContext as *const std::ffi::c_void,
    apply_control_token: UnsupportedStub as *const std::ffi::c_void,
    query_context_attributes_w: QueryContextAttributesW as *const std::ffi::c_void,
    impersonate_security_context: UnsupportedStub as *const std::ffi::c_void,
    revert_security_context: UnsupportedStub as *const std::ffi::c_void,
    make_signature: UnsupportedStub as *const std::ffi::c_void,
    verify_signature: UnsupportedStub as *const std::ffi::c_void,
    free_context_buffer: FreeContextBuffer as *const std::ffi::c_void,
    query_security_package_info_w: UnsupportedStub as *const std::ffi::c_void,
    reserved3: std::ptr::null(),
    reserved4: std::ptr::null(),
    export_security_context: UnsupportedStub as *const std::ffi::c_void,
    import_security_context_w: UnsupportedStub as *const std::ffi::c_void,
    query_security_context_token: UnsupportedStub as *const std::ffi::c_void,
    support_security_interface_w: UnsupportedStub as *const std::ffi::c_void,
    decrypt_message: UnsupportedStub as *const std::ffi::c_void,
    encrypt_message: UnsupportedStub as *const std::ffi::c_void,
};

/// Entry point returning a pointer to the ANSI `SecurityFunctionTable`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InitSecurityInterfaceA() -> *const SecurityFunctionTableA {
    &FUNCTION_TABLE_A
}

/// Entry point returning a pointer to the Unicode/Wide `SecurityFunctionTable`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn InitSecurityInterfaceW() -> *const SecurityFunctionTableW {
    &FUNCTION_TABLE_W
}
