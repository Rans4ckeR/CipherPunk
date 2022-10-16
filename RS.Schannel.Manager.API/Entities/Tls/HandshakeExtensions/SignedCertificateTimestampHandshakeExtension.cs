namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record SignedCertificateTimestampHandshakeExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.signed_certificate_timestamp));

    // 2 bytes
    public override byte[] ExtensionTypeLength { get => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0)); } // length 0

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);

        return result.ToArray();
    }
}