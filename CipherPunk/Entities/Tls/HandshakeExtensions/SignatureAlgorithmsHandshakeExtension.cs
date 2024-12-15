using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record SignatureAlgorithmsHandshakeExtension : HandshakeExtension
{
    public SignatureAlgorithmsHandshakeExtension(IEnumerable<TlsSignatureScheme> tlsSignatureSchemes)
        => ExtensionTypeSignatureAlgorithms = [.. tlsSignatureSchemes.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q)))];

    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.signature_algorithms));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeSignatureAlgorithmsLength.Length + ExtensionTypeSignatureAlgorithms.Length)));

    // 2 bytes
    public byte[] ExtensionTypeSignatureAlgorithmsLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ExtensionTypeSignatureAlgorithms.Length));

    // 2 bytes per item
    public byte[] ExtensionTypeSignatureAlgorithms { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(ExtensionTypeSignatureAlgorithmsLength);
        result.AddRange(ExtensionTypeSignatureAlgorithms);

        return [.. result];
    }
}