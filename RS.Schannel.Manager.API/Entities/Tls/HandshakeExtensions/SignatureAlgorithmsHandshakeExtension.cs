namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record SignatureAlgorithmsHandshakeExtension : HandshakeExtension
{
    public SignatureAlgorithmsHandshakeExtension(TlsSignatureScheme[] tlsSignatureSchemes)
    {
        ExtensionTypeSignatureAlgorithms = tlsSignatureSchemes.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q))).ToArray();
    }

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.signature_algorithms));

    // 2 bytes
    public override byte[] ExtensionTypeLength { get => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeSignatureAlgorithmsLength.Length + ExtensionTypeSignatureAlgorithms.Length))); }

    // 2 bytes
    public byte[] ExtensionTypeSignatureAlgorithmsLength { get => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ExtensionTypeSignatureAlgorithms.Length)); }

    // 2 bytes per item
    public byte[] ExtensionTypeSignatureAlgorithms { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(ExtensionTypeSignatureAlgorithmsLength);
        result.AddRange(ExtensionTypeSignatureAlgorithms);

        return result.ToArray();
    }
}