using System;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Text;
using IrcxSspi.Native;

namespace IrcxSspi.Interop;

internal static unsafe class SspiHelpers
{
	public static int AcquireInboundCredentials(string package, out IrcxSspiNative.CredHandle cred)
	{
		cred = default;
		ArgumentException.ThrowIfNullOrWhiteSpace(package);

		fixed (byte* pkgUtf8 = Encoding.ASCII.GetBytes(package + "\0"))
		{
			fixed (IrcxSspiNative.CredHandle* pCred = &cred)
			{
				return IrcxSspiNative.AcquireCredentialsHandleA(
					pszPrincipal: null,
					pszPackage: (sbyte*)pkgUtf8,
					fCredentialUse: IrcxSspiNative.SECPKG_CRED_INBOUND,
					pvLogonId: null,
					pAuthData: null,
					pGetKeyFn: null,
					pvGetKeyArgument: null,
					phCredential: pCred,
					ptsExpiry: null);
			}
		}
	}

	public static string? QueryContextUserName(ref IrcxSspiNative.CtxtHandle ctx)
	{
		IrcxSspiNative.SecPkgContext_NamesA names = default;
		fixed (IrcxSspiNative.CtxtHandle* pCtx = &ctx)
		{
			var rc = IrcxSspiNative.QueryContextAttributesA(pCtx, IrcxSspiNative.SECPKG_ATTR_NAMES, &names);
			if (rc != 0)
				return null;
		}

		try
		{
			if (names.sUserName == null)
				return null;

			return Marshal.PtrToStringAnsi((nint)names.sUserName);
		}
		finally
		{
			if (names.sUserName != null)
			{
				IrcxSspiNative.FreeContextBuffer(names.sUserName);
			}
		}
	}

	public static byte[] Escape(ReadOnlySpan<byte> bytes)
	{
		var buffer = new ArrayBufferWriter<byte>(bytes.Length * 2);
		foreach (var b in bytes)
		{
			switch (b)
			{
				case (byte)'\r': buffer.Write("\\r"u8); break;
				case (byte)'\n': buffer.Write("\\n"u8); break;
				case 0: buffer.Write("\\0"u8); break;
				case (byte)',': buffer.Write("\\c"u8); break;
				case (byte)'\t': buffer.Write("\\t"u8); break;
				case 0x20: buffer.Write("\\b"u8); break;
				case (byte)'\\': buffer.Write("\\\\"u8); break;
				default: buffer.GetSpan(1)[0] = b; buffer.Advance(1); break;
			}
		}
		return buffer.WrittenSpan.ToArray();
	}

	public static byte[] Unescape(ReadOnlySpan<byte> s)
	{
		var output = new byte[s.Length];
		var o = 0;
		for (var i = 0; i < s.Length; i++)
		{
			var b = s[i];
			if (b == (byte)'\\' && i + 1 < s.Length)
			{
				var next = s[i + 1];
				switch (next)
				{
					case (byte)'r': output[o++] = (byte)'\r'; i++; continue;
					case (byte)'n': output[o++] = (byte)'\n'; i++; continue;
					case (byte)'0': output[o++] = 0; i++; continue;
					case (byte)'c': output[o++] = (byte)','; i++; continue;
					case (byte)'t': output[o++] = (byte)'\t'; i++; continue;
					case (byte)'b': output[o++] = 0x20; i++; continue;
					case (byte)'\\': output[o++] = (byte)'\\'; i++; continue;
				}
			}
			output[o++] = b;
		}
		Array.Resize(ref output, o);
		return output;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static bool StartsWith(ReadOnlySpan<byte> value, ReadOnlySpan<byte> prefix) => value.Length >= prefix.Length && value[..prefix.Length].SequenceEqual(prefix);
}
