using System;
using System.Buffers;

namespace IrcxSspi.Interop;

internal static class ArrayBufferWriterExtensions
{
	public static void Write(this ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> data)
	{
		var span = writer.GetSpan(data.Length);
		data.CopyTo(span);
		writer.Advance(data.Length);
	}
}
