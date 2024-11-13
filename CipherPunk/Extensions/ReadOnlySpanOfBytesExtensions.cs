namespace CipherPunk;

internal static class ReadOnlySpanOfBytesExtensions
{
    public static byte TakeByte(this ReadOnlySpan<byte> data, ref int index) => data[index..++index][0];

    public static byte[] TakeBytes(this ReadOnlySpan<byte> data, ref int index, int size)
    {
        ReadOnlySpan<byte> bytes = data[index..(index + size)];

        index += size;

        return bytes.ToArray();
    }
}