using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record EncryptThenMacExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.encrypt_then_mac));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0)); // encrypt_then_mac

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);

        return [.. result];
    }
}