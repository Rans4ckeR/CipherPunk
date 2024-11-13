using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record ExtendedMasterSecretExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.extended_master_secret));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0)); // extended_master_secret

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);

        return [.. result];
    }
}