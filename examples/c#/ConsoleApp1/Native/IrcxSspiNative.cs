using System;
using System.Runtime.InteropServices;

namespace IrcxSspi.Native;

internal static unsafe partial class IrcxSspiNative
{
	internal enum SspiError : int
	{
		Ok = 0,
		ContinueNeeded = 0x00090312,
		UnknownCredentials = unchecked((int)0x8009030D),
		InvalidHandle = unchecked((int)0x80090301),
		NotSupported = unchecked((int)0x80090302),
		InvalidToken = unchecked((int)0x80090308),
		LogonDenied = unchecked((int)0x8009030C),
	}

	internal const int SECPKG_ATTR_NAMES = 1;

	internal const uint SECBUFFER_VERSION = 0;
	internal const uint SECBUFFER_TOKEN = 2;
	internal const uint SECBUFFER_PKG_PARAMS = 3;

	internal const uint SECPKG_CRED_INBOUND = 2;
	internal const uint SECURITY_NATIVE_DREP = 16;

	// On Windows, sspi.h defines these as ULONG_PTR fields, i.e. pointer-sized.
	[StructLayout(LayoutKind.Sequential)]
	internal struct CredHandle
	{
		public nuint dwLower;
		public nuint dwUpper;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct CtxtHandle
	{
		public nuint dwLower;
		public nuint dwUpper;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SecBuffer
	{
		public uint cbBuffer;
		public uint BufferType;
		public byte* pvBuffer;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SecBufferDesc
	{
		public uint ulVersion;
		public uint cBuffers;
		public SecBuffer* pBuffers;
	}

	[StructLayout(LayoutKind.Sequential)]
	internal struct SecPkgContext_NamesA
	{
		public sbyte* sUserName;
	}

	[DllImport("ircx_sspi", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
	internal static extern int AcquireCredentialsHandleA(
		sbyte* pszPrincipal,
		sbyte* pszPackage,
		uint fCredentialUse,
		void* pvLogonId,
		void* pAuthData,
		void* pGetKeyFn,
		void* pvGetKeyArgument,
		CredHandle* phCredential,
		nuint* ptsExpiry);

	[DllImport("ircx_sspi", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
	internal static extern int FreeCredentialsHandle(CredHandle* phCredential);

	[DllImport("ircx_sspi", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
	internal static extern int AcceptSecurityContext(
		CredHandle* phCredential,
		CtxtHandle* phContext,
		SecBufferDesc* pInput,
		uint fContextReq,
		uint TargetDataRep,
		CtxtHandle* phNewContext,
		SecBufferDesc* pOutput,
		uint* pfContextAttr,
		nuint* ptsExpiry);

	[DllImport("ircx_sspi", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
	internal static extern int DeleteSecurityContext(CtxtHandle* phContext);

	[DllImport("ircx_sspi", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
	internal static extern int QueryContextAttributesA(
		CtxtHandle* phContext,
		uint ulAttribute,
		void* pBuffer);

	[DllImport("ircx_sspi", CallingConvention = CallingConvention.Winapi, ExactSpelling = true)]
	internal static extern int FreeContextBuffer(void* pvContextBuffer);
}
