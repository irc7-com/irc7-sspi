using System;
using System.Threading;
using System.Threading.Tasks;
using IrcxSspi.Native;
using IrcxSspi.Server;

const int Port = 6667;

try
{
	IrcxSspiModule.Initialize();
	Console.WriteLine($"Initializing IRCX SSPI test server...");

	using var cts = new CancellationTokenSource();
	Console.CancelKeyPress += (_, e) =>
	{
		e.Cancel = true;
		cts.Cancel();
	};

	await IrcxAuthServer.RunAsync(Port, cts.Token);
}
catch (OperationCanceledException)
{
	Console.WriteLine("Server shutdown.");
}
catch (Exception ex)
{
	Console.Error.WriteLine($"Error: {ex}");
	Environment.Exit(1);
}

