# MSN Chat SSPI Security Providers

A high-fidelity, cross-platform implementation of standard Security Support Provider Interface (SSPI) authentication protocols. This suite replicates the legacy security providers originally utilized by the MSN Chat ActiveX controls, including **GateKeeper (GKSSP)** and **NTLM**.

This repository is designed with a dual-target architecture:
1. **Rust Library (`rlib`)**: Safe, modern Rust API with clean traits and explicit state-machine transitions.
2. **Native C/C++ Compatible DLL (`cdylib`)**: A standard, fully compliant Windows Security Support Provider (SSP) exposing the standard `InitSecurityInterfaceA` and `InitSecurityInterfaceW` entry points.

---

## Features

- **GateKeeper (GKSSP) v1, v2, & v3**: Authentic replication of the proprietary MSN Chat challenge-response mechanism. Supports version negotiation, hostname-based HMAC-MD5 input profiles, and legacy 32-byte vs. 48-byte token responses.
- **NTLM Simulation**: Clean wrapping of standard NTLMSSP negotiate-challenge-response sequences.
- **Dynamic Context Queries**: Fully supports standard `QueryContextAttributes` queries for `SECPKG_ATTR_NAMES` (identity verification) and process-safe layout-prefixed `FreeContextBuffer` deallocation.

---

## Build Instructions

Compile both the Rust static library and the native C/C++ dynamic library:

```bash
# Build both the Rust library (rlib) and standard SSPI DLL (cdylib)
cargo build

# Run the dynamic FFI dynamic integration test suite
cargo run --bin ircx-sspi-test
```

On Windows, this compiles to `target/debug/ircx_sspi.dll`. On Linux or macOS, it compiles to standard shared objects (`libircx_sspi.so` / `libircx_sspi.dylib`).

---

## FFI Integration Guide

To load this dynamic library natively in a C/C++ or dynamic loading application:

1. **Load the DLL / Shared Library**: Invoke `LoadLibraryA` (Windows) or `dlopen` (POSIX).
2. **Retrieve the Function Table**: Resolve `InitSecurityInterfaceA` (ANSI) or `InitSecurityInterfaceW` (Unicode) to retrieve a pointer to `SecurityFunctionTable`.
3. **Execute Handshakes**: Call the resolved function pointers (`AcquireCredentialsHandleA`, `InitializeSecurityContextA`, `AcceptSecurityContext`, `QueryContextAttributesA`, `FreeContextBuffer`).

---

## Code Examples

### 1. GateKeeper (GKSSP) FFI Example
The GateKeeper provider expects specific parameters in dynamic buffers:
- **Client Init (Step 1)**: Expects a client identifier string (GK ID) and server hostname passed in `SECBUFFER_PKG_PARAMS`. Optionally, a 4-byte little-endian integer version configuration can be passed.
- **Server Init (Step 1)**: Expects the target hostname in `SECBUFFER_PKG_PARAMS` to calculate HMAC signatures.

#### Client-Side Execution (C/C++ pseudocode):
```c
#include <windows.h>
#include <sspi.h>

// Resolve dynamic table
typedef PSecurityFunctionTableA (SEC_ENTRY *INIT_FN)();
HMODULE hDll = LoadLibraryA("ircx_sspi.dll");
INIT_FN InitSecurityInterfaceA = (INIT_FN)GetProcAddress(hDll, "InitSecurityInterfaceA");
PSecurityFunctionTableA pTable = InitSecurityInterfaceA();

// 1. Acquire client credentials
CredHandle hCred;
TimeStamp tsExpiry;
pTable->AcquireCredentialsHandleA(
    NULL, "GateKeeper", SECPKG_CRED_OUTBOUND, 
    NULL, NULL, NULL, NULL, &hCred, &tsExpiry
);

// 2. Prepare GateKeeper parameters
const char* gk_id = "GK_CLIENT_ID_TOK";
const char* hostname = "chat.msn.com";

SecBuffer params[2] = {
    { (ULONG)strlen(gk_id), SECBUFFER_PKG_PARAMS, (void*)gk_id },
    { (ULONG)strlen(hostname), SECBUFFER_PKG_PARAMS, (void*)hostname }
};
SecBufferDesc inputDesc = { SECBUFFER_VERSION, 2, params };

BYTE outToken[128];
SecBuffer outBuf = { sizeof(outToken), SECBUFFER_TOKEN, outToken };
SecBufferDesc outputDesc = { SECBUFFER_VERSION, 1, &outBuf };

CtxtHandle hContext;
ULONG contextAttr;
SECURITY_STATUS status = pTable->InitializeSecurityContextA(
    &hCred, NULL, NULL, 0, 0, SECURITY_NATIVE_DREP,
    &inputDesc, 0, &hContext, &outputDesc, &contextAttr, &tsExpiry
);
// status will be SEC_I_CONTINUE_NEEDED; outBuf.cbBuffer contains Step 1 Client token
```

---

### 2. NTLM Challenge-Response FFI Example
Standard NTLM relies entirely on sequential token buffer exchange. The initial `InitializeSecurityContext` is invoked with zero inputs.

#### Handshake Simulation (C/C++ pseudocode):
```c
// 1. Client Step 1: Generate Type 1 Negotiate Token
CredHandle hClientCred;
pTable->AcquireCredentialsHandleA(NULL, "NTLM", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL, &hClientCred, &tsExpiry);

CtxtHandle hClientCtx;
BYTE negotiateToken[128];
SecBuffer clientOut = { sizeof(negotiateToken), SECBUFFER_TOKEN, negotiateToken };
SecBufferDesc clientOutDesc = { SECBUFFER_VERSION, 1, &clientOut };
ULONG clientAttr;

pTable->InitializeSecurityContextA(
    &hClientCred, NULL, NULL, 0, 0, SECURITY_NATIVE_DREP,
    NULL, 0, &hClientCtx, &clientOutDesc, &clientAttr, &tsExpiry
); // Returns SEC_I_CONTINUE_NEEDED

// 2. Server Step 1: Process Negotiate, Generate Type 2 Challenge Token
CredHandle hServerCred;
pTable->AcquireCredentialsHandleA(NULL, "NTLM", SECPKG_CRED_INBOUND, NULL, NULL, NULL, NULL, &hServerCred, &tsExpiry);

CtxtHandle hServerCtx;
SecBuffer serverIn = { clientOut.cbBuffer, SECBUFFER_TOKEN, negotiateToken };
SecBufferDesc serverInDesc = { SECBUFFER_VERSION, 1, &serverIn };

BYTE challengeToken[256];
SecBuffer serverOut = { sizeof(challengeToken), SECBUFFER_TOKEN, challengeToken };
SecBufferDesc serverOutDesc = { SECBUFFER_VERSION, 1, &serverOut };
ULONG serverAttr;

pTable->AcceptSecurityContext(
    &hServerCred, NULL, &serverInDesc, 0, SECURITY_NATIVE_DREP,
    &hServerCtx, &serverOutDesc, &serverAttr, &tsExpiry
); // Returns SEC_I_CONTINUE_NEEDED

// 3. Client Step 2: Process Challenge, Generate Type 3 Authenticate Token
SecBuffer clientIn = { serverOut.cbBuffer, SECBUFFER_TOKEN, challengeToken };
SecBufferDesc clientInDesc = { SECBUFFER_VERSION, 1, &clientIn };

BYTE authenticateToken[512];
SecBuffer clientOut2 = { sizeof(authenticateToken), SECBUFFER_TOKEN, authenticateToken };
SecBufferDesc clientOut2Desc = { SECBUFFER_VERSION, 1, &clientOut2 };

pTable->InitializeSecurityContextA(
    &hClientCred, &hClientCtx, NULL, 0, 0, SECURITY_NATIVE_DREP,
    &clientInDesc, 0, &hClientCtx, &clientOut2Desc, &clientAttr, &tsExpiry
); // Returns SEC_E_OK (Client Handshake Completed)

// 4. Server Step 2: Finalize Authentication
SecBuffer serverIn2 = { clientOut2.cbBuffer, SECBUFFER_TOKEN, authenticateToken };
SecBufferDesc serverIn2Desc = { SECBUFFER_VERSION, 1, &serverIn2 };

pTable->AcceptSecurityContext(
    &hServerCred, &hServerCtx, &serverIn2Desc, 0, SECURITY_NATIVE_DREP,
    &hServerCtx, NULL, &serverAttr, &tsExpiry
); // Returns SEC_E_OK (Server Handshake Completed)
```

---

### 3. Querying Authenticated Identity (Username)
Once a handshake finishes (`SEC_E_OK`), you can safely query the identity associated with the session:

```c
SecPkgContext_NamesA names;
SECURITY_STATUS queryStatus = pTable->QueryContextAttributesA(
    &hServerCtx, SECPKG_ATTR_NAMES, &names
);

if (queryStatus == SEC_E_OK) {
    printf("Authenticated Identity: %s\n", names.sUserName);
    
    // Always release FFI memory through the table's FreeContextBuffer
    pTable->FreeContextBuffer(names.sUserName);
}
```

---

## Memory Management

Any pointers allocated by `QueryContextAttributesA` or `QueryContextAttributesW` (like `sUserName` inside the names structures) **must** be released using the matching `FreeContextBuffer` FFI function pointer resolved from the SSP `SecurityFunctionTable`. 

Our FFI layer allocates these buffers with a custom layout-prefixed size tag. Freeing memory using standard system `free` or standard allocator calls outside this table will corrupt the memory heap.
