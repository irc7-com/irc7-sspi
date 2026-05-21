# MSN Chat SSPI Security Providers for C# (P/Invoke)

This guide explains how to dynamically load and utilize the compiled standard SSPI dynamic library (`ircx_sspi.dll` / `libircx_sspi.so`) in C# using .NET Platform Invoke (P/Invoke) services.

---

## 1. Marshalling Types & Structures

To match standard Visual C++ alignment (`repr(C)`), all SSPI structures must be declared with sequential layout:

```csharp
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct CredHandle
{
    public UIntPtr dwLower;
    public UIntPtr dwUpper;
}

[StructLayout(LayoutKind.Sequential)]
public struct CtxtHandle
{
    public UIntPtr dwLower;
    public UIntPtr dwUpper;
}

[StructLayout(LayoutKind.Sequential)]
public struct SecBuffer
{
    public uint cbBuffer;
    public uint BufferType;
    public IntPtr pvBuffer;
}

[StructLayout(LayoutKind.Sequential)]
public struct SecBufferDesc
{
    public uint ulVersion;
    public uint cBuffers;
    public IntPtr pBuffers; // Pointer to SecBuffer array
}

[StructLayout(LayoutKind.Sequential)]
public struct SecPkgContext_NamesA
{
    public IntPtr sUserName; // Pointer to null-terminated ANSI string
}
```

---

## 2. Dynamic Function Table Layout

In standard SSPI design, rather than calling native exports directly, it is highly recommended to resolve `InitSecurityInterfaceA` to retrieve the entire function table of pointers, which is then mapped to dynamic C# delegates:

```csharp
[StructLayout(LayoutKind.Sequential)]
public struct SecurityFunctionTableA
{
    public uint dwVersion;
    public IntPtr EnumerateSecurityPackagesA;
    public IntPtr QueryCredentialsAttributesA;
    public IntPtr AcquireCredentialsHandleA;
    public IntPtr FreeCredentialsHandle;
    public IntPtr Reserved2;
    public IntPtr InitializeSecurityContextA;
    public IntPtr AcceptSecurityContext;
    public IntPtr CompleteAuthToken;
    public IntPtr DeleteSecurityContext;
    public IntPtr ApplyControlToken;
    public IntPtr QueryContextAttributesA;
    public IntPtr ImpersonateSecurityContext;
    public IntPtr RevertSecurityContext;
    public IntPtr MakeSignature;
    public IntPtr VerifySignature;
    public IntPtr FreeContextBuffer;
    public IntPtr QuerySecurityPackageInfoA;
    public IntPtr Reserved3;
    public IntPtr Reserved4;
    public IntPtr ExportSecurityContext;
    public IntPtr ImportSecurityContextA;
    public IntPtr QuerySecurityContextToken;
    public IntPtr SupportSecurityInterfaceA;
    public IntPtr DecryptMessage;
    public IntPtr EncryptMessage;
}
```

---

## 3. Dynamic Native Loader

Since our SSP library is cross-platform, we resolve the table dynamically at runtime:

```csharp
public static class SspiLoader
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr LoadLibraryA(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    // delegates matching the table signatures
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr InitSecurityInterfaceADelegate();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi)]
    public delegate int AcquireCredentialsHandleADelegate(
        string pszPrincipal,
        string pszPackage,
        uint fCredentialUse,
        IntPtr pvLogonID,
        IntPtr pAuthData,
        IntPtr pGetKeyFn,
        IntPtr pvGetKeyArgument,
        ref CredHandle phCredential,
        ref ulong ptsExpiry
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int FreeCredentialsHandleDelegate(ref CredHandle phCredential);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int InitializeSecurityContextADelegate(
        ref CredHandle phCredential,
        IntPtr phContext, // Pointer to CtxtHandle or null
        string pszTargetName,
        uint fContextReq,
        uint Reserved1,
        uint TargetDataRep,
        IntPtr pInput, // Pointer to SecBufferDesc or null
        uint Reserved2,
        ref CtxtHandle phNewContext,
        ref SecBufferDesc pOutput,
        ref uint pfContextAttr,
        ref ulong ptsExpiry
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int AcceptSecurityContextDelegate(
        ref CredHandle phCredential,
        IntPtr phContext,
        IntPtr pInput,
        uint fContextReq,
        uint TargetDataRep,
        ref CtxtHandle phNewContext,
        ref SecBufferDesc pOutput,
        ref uint pfContextAttr,
        ref ulong ptsExpiry
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int DeleteSecurityContextDelegate(ref CtxtHandle phContext);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int QueryContextAttributesADelegate(
        ref CtxtHandle phContext,
        uint ulAttribute,
        IntPtr pBuffer
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int FreeContextBufferDelegate(IntPtr pv);

    public static SecurityFunctionTableA LoadTable(string dllPath)
    {
        IntPtr hModule = LoadLibraryA(dllPath);
        if (hModule == IntPtr.Zero)
            throw new Exception($"Failed to load library: {dllPath}");

        IntPtr pInit = GetProcAddress(hModule, "InitSecurityInterfaceA");
        if (pInit == IntPtr.Zero)
            throw new Exception("Could not find InitSecurityInterfaceA");

        var initFn = Marshal.GetDelegateForFunctionPointer<InitSecurityInterfaceADelegate>(pInit);
        IntPtr pTable = initFn();
        return Marshal.PtrToStructure<SecurityFunctionTableA>(pTable);
    }
}
```

---

## 4. Server-Side Handshake Example (AcceptSecurityContext / ASC)

Below is a complete execution sequence representing the server-side (`AcceptSecurityContext` / ASC) handshake of **GateKeeper** in C#.

### GateKeeper Server Handshake Setup

```csharp
public static void RunGateKeeperServerHandshake(
    SecurityFunctionTableA table, 
    byte[] step1ClientToken, 
    byte[] step2ClientToken)
{
    var acquireCred = Marshal.GetDelegateForFunctionPointer<SspiLoader.AcquireCredentialsHandleADelegate>(table.AcquireCredentialsHandleA);
    var acceptCtx = Marshal.GetDelegateForFunctionPointer<SspiLoader.AcceptSecurityContextDelegate>(table.AcceptSecurityContext);
    var freeCred = Marshal.GetDelegateForFunctionPointer<SspiLoader.FreeCredentialsHandleDelegate>(table.FreeCredentialsHandle);
    var deleteCtx = Marshal.GetDelegateForFunctionPointer<SspiLoader.DeleteSecurityContextDelegate>(table.DeleteSecurityContext);

    // 1. Acquire Server Inbound Credentials
    CredHandle serverCred = new CredHandle();
    ulong expiry = 0;
    // credUse = 2 (SECPKG_CRED_INBOUND)
    acquireCred(null, "GateKeeper", 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref serverCred, ref expiry);

    // 2. Prepare Step 1 Inputs (Step 1 Client Token + Server Hostname PkgParams)
    byte[] hostname = System.Text.Encoding.ASCII.GetBytes("chat.msn.com");

    IntPtr pClientToken = Marshal.AllocHGlobal(step1ClientToken.Length);
    IntPtr pHost = Marshal.AllocHGlobal(hostname.Length);
    Marshal.Copy(step1ClientToken, 0, pClientToken, step1ClientToken.Length);
    Marshal.Copy(hostname, 0, pHost, hostname.Length);

    // Array of 2 SecBuffers for input: [Token, PkgParams]
    SecBuffer[] step1Inputs = new SecBuffer[2];
    step1Inputs[0] = new SecBuffer { cbBuffer = (uint)step1ClientToken.Length, BufferType = 2 /* TOKEN */, pvBuffer = pClientToken };
    step1Inputs[1] = new SecBuffer { cbBuffer = (uint)hostname.Length, BufferType = 3 /* PKG_PARAMS */, pvBuffer = pHost };

    IntPtr pStep1Inputs = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>() * 2);
    Marshal.StructureToPtr(step1Inputs[0], pStep1Inputs, false);
    Marshal.StructureToPtr(step1Inputs[1], pStep1Inputs + Marshal.SizeOf<SecBuffer>(), false);

    SecBufferDesc inputDesc = new SecBufferDesc
    {
        ulVersion = 0,
        cBuffers = 2,
        pBuffers = pStep1Inputs
    };

    IntPtr pInputDesc = Marshal.AllocHGlobal(Marshal.SizeOf<SecBufferDesc>());
    Marshal.StructureToPtr(inputDesc, pInputDesc, false);

    // Prepare Output Buffer for Server Challenge (Step 1 Server Token)
    IntPtr pServerOutToken = Marshal.AllocHGlobal(128);
    SecBuffer outBuf = new SecBuffer { cbBuffer = 128, BufferType = 2 /* TOKEN */, pvBuffer = pServerOutToken };
    SecBufferDesc outputDesc = new SecBufferDesc
    {
        ulVersion = 0,
        cBuffers = 1,
        pBuffers = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>())
    };
    Marshal.StructureToPtr(outBuf, outputDesc.pBuffers, false);

    // 3. Process Step 1 (AcceptSecurityContext) -> Generates Challenge
    CtxtHandle serverCtx = new CtxtHandle();
    uint attr = 0;
    int status1 = acceptCtx(ref serverCred, IntPtr.Zero, pInputDesc, 0, 16, ref serverCtx, ref outputDesc, ref attr, ref expiry);

    if (status1 == 0x00090312) // SEC_I_CONTINUE_NEEDED
    {
        // Read challenge token from output
        SecBuffer updatedOutBuf = Marshal.PtrToStructure<SecBuffer>(outputDesc.pBuffers);
        byte[] challengeBytes = new byte[updatedOutBuf.cbBuffer];
        Marshal.Copy(updatedOutBuf.pvBuffer, challengeBytes, 0, (int)updatedOutBuf.cbBuffer);
        Console.WriteLine($"Server Step 1 processed. Generated challenge of {challengeBytes.Length} bytes.");
    }

    // Free Step 1 unmanaged input/output allocations
    Marshal.FreeHGlobal(pClientToken);
    Marshal.FreeHGlobal(pHost);
    Marshal.FreeHGlobal(pStep1Inputs);
    Marshal.FreeHGlobal(pInputDesc);
    Marshal.FreeHGlobal(pServerOutToken);
    Marshal.FreeHGlobal(outputDesc.pBuffers);

    // 4. Prepare Step 2 Inputs (Step 2 Client Token)
    IntPtr pClientToken2 = Marshal.AllocHGlobal(step2ClientToken.Length);
    Marshal.Copy(step2ClientToken, 0, pClientToken2, step2ClientToken.Length);

    SecBuffer[] step2Inputs = new SecBuffer[1];
    step2Inputs[0] = new SecBuffer { cbBuffer = (uint)step2ClientToken.Length, BufferType = 2 /* TOKEN */, pvBuffer = pClientToken2 };

    IntPtr pStep2Inputs = Marshal.AllocHGlobal(Marshal.SizeOf<SecBuffer>());
    Marshal.StructureToPtr(step2Inputs[0], pStep2Inputs, false);

    SecBufferDesc inputDesc2 = new SecBufferDesc
    {
        ulVersion = 0,
        cBuffers = 1,
        pBuffers = pStep2Inputs
    };

    IntPtr pInputDesc2 = Marshal.AllocHGlobal(Marshal.SizeOf<SecBufferDesc>());
    Marshal.StructureToPtr(inputDesc2, pInputDesc2, false);

    // Prepare dummy output description (since no step 3 token is needed for GateKeeper)
    SecBufferDesc outputDesc2 = new SecBufferDesc { ulVersion = 0, cBuffers = 0, pBuffers = IntPtr.Zero };

    // Pass the existing context handle back to acceptCtx to complete it
    IntPtr pCtxHandle = Marshal.AllocHGlobal(Marshal.SizeOf<CtxtHandle>());
    Marshal.StructureToPtr(serverCtx, pCtxHandle, false);

    // 5. Process Step 2 -> Completes Authentication
    int status2 = acceptCtx(ref serverCred, pCtxHandle, pInputDesc2, 0, 16, ref serverCtx, ref outputDesc2, ref attr, ref expiry);

    if (status2 == 0) // SEC_E_OK
    {
        Console.WriteLine("GateKeeper Server authentication succeeded!");
        
        // 6. Query identified username
        string username = RetrieveIdentity(table, ref serverCtx);
        Console.WriteLine($"Authenticated Client Username: {username}");
    }

    // Clean up all Step 2 allocations
    Marshal.FreeHGlobal(pClientToken2);
    Marshal.FreeHGlobal(pStep2Inputs);
    Marshal.FreeHGlobal(pInputDesc2);
    Marshal.FreeHGlobal(pCtxHandle);

    deleteCtx(ref serverCtx);
    freeCred(ref serverCred);
}
```

---

## 5. Querying Context Identity safely

Once authentication reaches completion (`SEC_E_OK` / `0`), query the server's context for the username. Marshalling the unmanaged ANSI string requires retrieving the pointer from the native layout and freeing it through `FreeContextBuffer` to prevent heap leaks:

```csharp
public static string RetrieveIdentity(SecurityFunctionTableA table, ref CtxtHandle completedContext)
{
    var queryAttr = Marshal.GetDelegateForFunctionPointer<SspiLoader.QueryContextAttributesADelegate>(table.QueryContextAttributesA);
    var freeCtxBuf = Marshal.GetDelegateForFunctionPointer<SspiLoader.FreeContextBufferDelegate>(table.FreeContextBuffer);

    IntPtr pNames = Marshal.AllocHGlobal(Marshal.SizeOf<SecPkgContext_NamesA>());
    
    // SECPKG_ATTR_NAMES = 1
    int res = queryAttr(ref completedContext, 1, pNames);
    if (res == 0) // SEC_E_OK
    {
        SecPkgContext_NamesA names = Marshal.PtrToStructure<SecPkgContext_NamesA>(pNames);
        string username = Marshal.PtrToStringAnsi(names.sUserName);
        
        // IMPORTANT: Must release allocation using the resolved FFI table deallocator!
        freeCtxBuf(names.sUserName);
        
        Marshal.FreeHGlobal(pNames);
        return username;
    }
    
    Marshal.FreeHGlobal(pNames);
    throw new Exception($"Failed to retrieve identity. SSPI code: {res}");
}
```
