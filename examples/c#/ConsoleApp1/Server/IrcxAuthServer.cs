using System;
using System.Buffers;
using System.Net;
using System.Net.Sockets;
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

	private sealed unsafe class Session : IDisposable
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
				unsafe { _ = IrcxSspiNative.DeleteSecurityContext(&ctx); }
				HasContext = false;
				Context = default;
			}
			if (HasCred)
			{
				var cred = Cred;
				unsafe { _ = IrcxSspiNative.FreeCredentialsHandle(&cred); }
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

	private static unsafe AuthOutcome ProcessAuth(string package, char stage, byte[] payload, Session session)
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
				_ = IrcxSspiNative.DeleteSecurityContext(&ctx);
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
			var (rc, newCtx, outToken) = Accept(session.Cred, context: &ctx, unescaped, includePkgParams: false);
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
				_ = IrcxSspiNative.DeleteSecurityContext(&finalCtx);
				session.Dispose();
				session.Reset();
				return AuthOutcome.Success(username + "@" + package);
			}

			// On failure, clean up the old context.
			{
				var old = session.Context;
				_ = IrcxSspiNative.DeleteSecurityContext(&old);
				session.Dispose();
				session.Reset();
			}
			throw new InvalidOperationException($"AcceptSecurityContext failed: 0x{rc:X8}");
		}

		throw new InvalidOperationException("Unsupported stage");
	}

	private static unsafe (int Rc, IrcxSspiNative.CtxtHandle NewContext, byte[] OutToken) Accept(
		IrcxSspiNative.CredHandle cred,
		IrcxSspiNative.CtxtHandle* context,
		byte[] tokenBytes,
		bool includePkgParams)
	{
		IrcxSspiNative.CtxtHandle newCtx = default;
		uint attrs = 0;
		var rc = 0;
		var actualLen = 0;

		var inputBuffersCount = includePkgParams ? 3 : 1;
		Span<IrcxSspiNative.SecBuffer> inBuffers = stackalloc IrcxSspiNative.SecBuffer[inputBuffersCount];
		Span<byte> hostBytes = stackalloc byte["localhost".Length + 1];
		"localhost"u8.CopyTo(hostBytes);
		hostBytes[^1] = 0;
		Span<byte> compat = stackalloc byte[1];
		compat[0] = 1;

		var outToken = new byte[4096];

		fixed (byte* tokenPtr = tokenBytes)
		fixed (byte* outPtr = outToken)
		fixed (byte* hostPtr = hostBytes)
		fixed (byte* compatPtr = compat)
		{
			inBuffers[0] = new IrcxSspiNative.SecBuffer { BufferType = IrcxSspiNative.SECBUFFER_TOKEN, cbBuffer = (uint)tokenBytes.Length, pvBuffer = tokenPtr };
			if (includePkgParams)
			{
				inBuffers[1] = new IrcxSspiNative.SecBuffer { BufferType = IrcxSspiNative.SECBUFFER_PKG_PARAMS, cbBuffer = (uint)(hostBytes.Length - 1), pvBuffer = hostPtr };
				inBuffers[2] = new IrcxSspiNative.SecBuffer { BufferType = IrcxSspiNative.SECBUFFER_PKG_PARAMS, cbBuffer = 1, pvBuffer = compatPtr };
			}

			fixed (IrcxSspiNative.SecBuffer* pIn = inBuffers)
			{
				var inDesc = new IrcxSspiNative.SecBufferDesc { ulVersion = IrcxSspiNative.SECBUFFER_VERSION, cBuffers = (uint)inputBuffersCount, pBuffers = pIn };
				Span<IrcxSspiNative.SecBuffer> outBuffers = stackalloc IrcxSspiNative.SecBuffer[1];
				outBuffers[0] = new IrcxSspiNative.SecBuffer { BufferType = IrcxSspiNative.SECBUFFER_TOKEN, cbBuffer = (uint)outToken.Length, pvBuffer = outPtr };
				fixed (IrcxSspiNative.SecBuffer* pOut = outBuffers)
				{
					var outDesc = new IrcxSspiNative.SecBufferDesc { ulVersion = IrcxSspiNative.SECBUFFER_VERSION, cBuffers = 1, pBuffers = pOut };
					rc = IrcxSspiNative.AcceptSecurityContext(&cred, context, &inDesc, 0, IrcxSspiNative.SECURITY_NATIVE_DREP, &newCtx, &outDesc, &attrs, null);
					actualLen = (int)outBuffers[0].cbBuffer;
				}
			}
		}

		if (actualLen < 0) actualLen = 0;
		Array.Resize(ref outToken, actualLen);
		return (rc, newCtx, outToken);
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
