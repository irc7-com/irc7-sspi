using System;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrcxSspi.Interop;
using IrcxSspi.Native;

namespace IrcxSspi.Server;

internal static class IrcxAuthServer
{
	private enum AuthOutcomeKind { Continue, Success }

	private sealed record AuthOutcome(AuthOutcomeKind Kind, byte[]? Token, string? UserName)
	{
		public static AuthOutcome Continue(byte[] token) => new(AuthOutcomeKind.Continue, token, null);
		public static AuthOutcome Success(string userName) => new(AuthOutcomeKind.Success, null, userName);
	}

	private sealed class Session : IDisposable
	{
		public string? ActivePackage;
		public IrcxSspiNative.CtxtHandle Context;
		public bool HasContext;
		public IrcxSspiNative.CredHandle Cred;
		public bool HasCred;

		public void Reset()
		{
			ActivePackage = null;
			HasContext = false;
			Context = default;
			HasCred = false;
			Cred = default;
		}

		public void Dispose()
		{
			if (HasContext)
			{
				var ctx = Context;
				_ = IrcxSspiNative.DeleteSecurityContext(ref ctx);
				HasContext = false;
				Context = default;
			}
			if (HasCred)
			{
				var cred = Cred;
				_ = IrcxSspiNative.FreeCredentialsHandle(ref cred);
				HasCred = false;
				Cred = default;
			}
			ActivePackage = null;
		}
	}

	public static async Task RunAsync(int port, CancellationToken cancellationToken)
	{
		var listener = new TcpListener(IPAddress.Any, port);
		if (listener.Server.AddressFamily == AddressFamily.InterNetworkV6)
			listener.Server.DualMode = true;
		listener.Start();

		Console.WriteLine($"IRCX SSPI test server listening on port {port}...");

		while (!cancellationToken.IsCancellationRequested)
		{
			var client = await listener.AcceptTcpClientAsync(cancellationToken);
			_ = Task.Run(() => HandleClientAsync(client, cancellationToken), cancellationToken);
		}
	}

	private static async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
	{
		using var _ = client;
		var endpoint = client.Client.RemoteEndPoint;
		Console.WriteLine($"New connection from: {endpoint}");

		using var session = new Session();
		using var stream = client.GetStream();
		var readBuffer = ArrayPool<byte>.Shared.Rent(4096);
		try
		{
			var incoming = new ArrayBufferWriter<byte>(4096);

			while (!cancellationToken.IsCancellationRequested)
			{
				var bytesRead = await stream.ReadAsync(readBuffer, cancellationToken);
				if (bytesRead == 0)
				{
					Console.WriteLine("Connection closed by client");
					return;
				}

				incoming.Write(readBuffer.AsSpan(0, bytesRead));
				incoming = ProcessLines(incoming, session, stream, cancellationToken);
			}
		}
		catch (OperationCanceledException)
		{
			// ignore
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(readBuffer);
		}
	}

	private static ArrayBufferWriter<byte> ProcessLines(ArrayBufferWriter<byte> incoming, Session session, NetworkStream stream, CancellationToken ct)
	{
		var span = incoming.WrittenSpan;

		var start = 0;
		for (var i = 0; i < span.Length; i++)
		{
			var b = span[i];
			if (b is (byte)'\r' or (byte)'\n')
			{
				if (i > start)
				{
					var line = span.Slice(start, i - start);
					HandleLine(line, session, stream, ct);
				}
				start = i + 1;
			}
		}

		if (start == 0)
			return incoming;

		// drain processed bytes
		var remaining = span.Slice(start).ToArray();
		var next = new ArrayBufferWriter<byte>(Math.Max(4096, remaining.Length));
		next.Write(remaining);
		return next;
	}

	private static void HandleLine(ReadOnlySpan<byte> line, Session session, NetworkStream stream, CancellationToken ct)
	{
		// Log raw line for parity with Rust example.
		Console.WriteLine($"<- {Encoding.Latin1.GetString(line)}");

		if (!TryParseAuthLine(line, out var package, out var stage, out var payload))
			return;

		var outcome = ProcessAuth(package, stage, payload, session);
		switch (outcome.Kind)
		{
			case AuthOutcomeKind.Continue:
			{
				var escaped = SspiHelpers.Escape(outcome.Token!);
				var response = $"AUTH {package} S :{Encoding.Latin1.GetString(escaped)}\r\n";
				Console.WriteLine($"-> {response.TrimEnd()} ");
				// Intentionally synchronous for tiny responses; avoids async overhead in the line handler.
				stream.Write(Encoding.Latin1.GetBytes(response));
				break;
			}
			case AuthOutcomeKind.Success:
			{
				var response = $"AUTH {package} * {outcome.UserName} 0\r\n";
				Console.WriteLine($"-> {response.TrimEnd()} ");
				// Intentionally synchronous for tiny responses; avoids async overhead in the line handler.
				stream.Write(Encoding.Latin1.GetBytes(response));
				break;
			}
		}
	}

	private static AuthOutcome ProcessAuth(string package, char stage, byte[] payload, Session session)
	{
		if (!string.Equals(package, "GateKeeper", StringComparison.Ordinal))
			throw new InvalidOperationException("Unsupported package");

		var unescaped = SspiHelpers.Unescape(payload);

		if (stage == 'I')
		{
			session.Dispose();
			session.Reset();
			session.ActivePackage = package;

			var rcCred = SspiHelpers.AcquireInboundCredentials(package, out var cred);
			if (rcCred != 0)
				throw new InvalidOperationException($"AcquireCredentialsHandleA failed: 0x{rcCred:X8}");
			session.Cred = cred;
			session.HasCred = true;

			var (rc, newCtx, outToken) = Accept(session.Cred, context: null, unescaped, includePkgParams: true);
			if (rc == (int)IrcxSspiNative.SspiError.ContinueNeeded)
			{
				session.Context = newCtx;
				session.HasContext = true;
				return AuthOutcome.Continue(outToken);
			}
			if (rc == 0)
			{
				var ctx = newCtx;
				var username = SspiHelpers.QueryContextUserName(ref ctx) ?? "Unknown";
				_ = IrcxSspiNative.DeleteSecurityContext(ref ctx);
				session.Dispose();
				session.Reset();
				return AuthOutcome.Success(username + "@" + package);
			}

			throw new InvalidOperationException($"AcceptSecurityContext failed: 0x{rc:X8}");
		}

		if (stage == 'S')
		{
			if (!session.HasContext || session.ActivePackage is null || !string.Equals(session.ActivePackage, package, StringComparison.Ordinal))
				throw new InvalidOperationException("Invalid session state");

			if (!session.HasCred)
				throw new InvalidOperationException("Missing credentials handle");

			var ctx = session.Context;
			var (rc, newCtx, outToken) = Accept(session.Cred, context: ctx, unescaped, includePkgParams: false);
			if (rc == (int)IrcxSspiNative.SspiError.ContinueNeeded)
			{
				session.Context = newCtx;
				session.HasContext = true;
				return AuthOutcome.Continue(outToken);
			}
			if (rc == 0)
			{
				var finalCtx = newCtx;
				var username = SspiHelpers.QueryContextUserName(ref finalCtx) ?? "Unknown";
				_ = IrcxSspiNative.DeleteSecurityContext(ref finalCtx);
				session.Dispose();
				session.Reset();
				return AuthOutcome.Success(username + "@" + package);
			}

			// On failure, clean up the old context.
			{
				var old = session.Context;
				_ = IrcxSspiNative.DeleteSecurityContext(ref old);
				session.Dispose();
				session.Reset();
			}
			throw new InvalidOperationException($"AcceptSecurityContext failed: 0x{rc:X8}");
		}

		throw new InvalidOperationException("Unsupported stage");
	}

	private static (int Rc, IrcxSspiNative.CtxtHandle NewContext, byte[] OutToken) Accept(
		IrcxSspiNative.CredHandle cred,
		IrcxSspiNative.CtxtHandle? context,
		byte[] tokenBytes,
		bool includePkgParams)
	{
		IrcxSspiNative.CtxtHandle newCtx = default;
		uint attrs = 0;
		nuint expiry = 0;
		const int outCapacity = 4096;

		var tokenPtr = IntPtr.Zero;
		var outTokenPtr = IntPtr.Zero;
		var hostPtr = IntPtr.Zero;
		var compatPtr = IntPtr.Zero;
		var inBuffersPtr = IntPtr.Zero;
		var outBuffersPtr = IntPtr.Zero;
		var inDescPtr = IntPtr.Zero;
		var outDescPtr = IntPtr.Zero;
		var contextPtr = IntPtr.Zero;

		try
		{
			tokenPtr = Marshal.AllocHGlobal(tokenBytes.Length);
			if (tokenBytes.Length > 0)
				Marshal.Copy(tokenBytes, 0, tokenPtr, tokenBytes.Length);

			outTokenPtr = Marshal.AllocHGlobal(outCapacity);

			var inputBuffersCount = includePkgParams ? 3 : 1;
			var inBuffers = new IrcxSspiNative.SecBuffer[inputBuffersCount];
			inBuffers[0] = new IrcxSspiNative.SecBuffer
			{
				BufferType = IrcxSspiNative.SECBUFFER_TOKEN,
				cbBuffer = (uint)tokenBytes.Length,
				pvBuffer = tokenPtr,
			};

			if (includePkgParams)
			{
				var hostBytes = Encoding.ASCII.GetBytes("localhost");
				hostPtr = Marshal.AllocHGlobal(hostBytes.Length + 1);
				Marshal.Copy(hostBytes, 0, hostPtr, hostBytes.Length);
				Marshal.WriteByte(hostPtr, hostBytes.Length, 0);

				compatPtr = Marshal.AllocHGlobal(1);
				Marshal.WriteByte(compatPtr, 0, 1);

				inBuffers[1] = new IrcxSspiNative.SecBuffer
				{
					BufferType = IrcxSspiNative.SECBUFFER_PKG_PARAMS,
					cbBuffer = (uint)hostBytes.Length,
					pvBuffer = hostPtr,
				};
				inBuffers[2] = new IrcxSspiNative.SecBuffer
				{
					BufferType = IrcxSspiNative.SECBUFFER_PKG_PARAMS,
					cbBuffer = 1,
					pvBuffer = compatPtr,
				};
			}

			inBuffersPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IrcxSspiNative.SecBuffer>() * inputBuffersCount);
			for (var i = 0; i < inputBuffersCount; i++)
			{
				Marshal.StructureToPtr(inBuffers[i], IntPtr.Add(inBuffersPtr, i * Marshal.SizeOf<IrcxSspiNative.SecBuffer>()), false);
			}

			var outBuffer = new IrcxSspiNative.SecBuffer
			{
				BufferType = IrcxSspiNative.SECBUFFER_TOKEN,
				cbBuffer = outCapacity,
				pvBuffer = outTokenPtr,
			};
			outBuffersPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IrcxSspiNative.SecBuffer>());
			Marshal.StructureToPtr(outBuffer, outBuffersPtr, false);

			var inDesc = new IrcxSspiNative.SecBufferDesc
			{
				ulVersion = IrcxSspiNative.SECBUFFER_VERSION,
				cBuffers = (uint)inputBuffersCount,
				pBuffers = inBuffersPtr,
			};
			var outDesc = new IrcxSspiNative.SecBufferDesc
			{
				ulVersion = IrcxSspiNative.SECBUFFER_VERSION,
				cBuffers = 1,
				pBuffers = outBuffersPtr,
			};

			inDescPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IrcxSspiNative.SecBufferDesc>());
			Marshal.StructureToPtr(inDesc, inDescPtr, false);
			outDescPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IrcxSspiNative.SecBufferDesc>());
			Marshal.StructureToPtr(outDesc, outDescPtr, false);

			if (context.HasValue)
			{
				contextPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IrcxSspiNative.CtxtHandle>());
				Marshal.StructureToPtr(context.Value, contextPtr, false);
			}

			var rc = IrcxSspiNative.AcceptSecurityContext(
				ref cred,
				contextPtr,
				inDescPtr,
				0,
				IrcxSspiNative.SECURITY_NATIVE_DREP,
				ref newCtx,
				outDescPtr,
				ref attrs,
				ref expiry);

			var outSecBuffer = Marshal.PtrToStructure<IrcxSspiNative.SecBuffer>(outBuffersPtr);
			var actualLen = Math.Clamp((int)outSecBuffer.cbBuffer, 0, outCapacity);
			var outToken = new byte[actualLen];
			if (actualLen > 0)
				Marshal.Copy(outTokenPtr, outToken, 0, actualLen);

			return (rc, newCtx, outToken);
		}
		finally
		{
			if (contextPtr != IntPtr.Zero) Marshal.FreeHGlobal(contextPtr);
			if (inDescPtr != IntPtr.Zero) Marshal.FreeHGlobal(inDescPtr);
			if (outDescPtr != IntPtr.Zero) Marshal.FreeHGlobal(outDescPtr);
			if (inBuffersPtr != IntPtr.Zero) Marshal.FreeHGlobal(inBuffersPtr);
			if (outBuffersPtr != IntPtr.Zero) Marshal.FreeHGlobal(outBuffersPtr);
			if (compatPtr != IntPtr.Zero) Marshal.FreeHGlobal(compatPtr);
			if (hostPtr != IntPtr.Zero) Marshal.FreeHGlobal(hostPtr);
			if (outTokenPtr != IntPtr.Zero) Marshal.FreeHGlobal(outTokenPtr);
			if (tokenPtr != IntPtr.Zero) Marshal.FreeHGlobal(tokenPtr);
		}
	}

	private static bool TryParseAuthLine(ReadOnlySpan<byte> line, out string package, out char stage, out byte[] payload)
	{
		package = string.Empty;
		stage = default;
		payload = Array.Empty<byte>();

		if (!SspiHelpers.StartsWith(line, "AUTH "u8))
			return false;

		var rest = line[5..];
		var space1 = rest.IndexOf((byte)' ');
		if (space1 <= 0)
			return false;

		package = Encoding.Latin1.GetString(rest[..space1]);
		rest = rest[(space1 + 1)..];

		if (rest.Length == 0)
			return false;
		stage = (char)rest[0];
		if (stage is not ('I' or 'S'))
			return false;

		// Format: "AUTH <Package> <Stage> :<payload>" (payload can be empty)
		var afterStage = rest.Length > 1 ? rest[1..] : ReadOnlySpan<byte>.Empty;
		if (afterStage.Length > 0 && afterStage[0] == (byte)' ')
			afterStage = afterStage[1..];
		if (afterStage.Length > 0 && afterStage[0] == (byte)':')
			afterStage = afterStage[1..];

		payload = afterStage.ToArray();
		return true;
	}
}
