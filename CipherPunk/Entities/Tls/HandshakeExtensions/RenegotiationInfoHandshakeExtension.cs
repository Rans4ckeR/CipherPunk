namespace CipherPunk;

using System.Buffers.Binary;

public sealed record RenegotiationInfoHandshakeExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.renegotiation_info));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)1));

    public static byte ExtensionTypeRenegotiationInfoLength => 0x00; // length 0, because of new connection

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(ExtensionTypeRenegotiationInfoLength);

        return [.. result];
    }
}