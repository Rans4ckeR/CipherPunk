namespace CipherPunk;

using System.Buffers.Binary;

public sealed record CompressCertificateHandshakeExtension : HandshakeExtension
{
    public CompressCertificateHandshakeExtension(TlsCertificateCompressionAlgorithm[] tlsCertificateCompressionAlgorithms)
        => CertificateCompressionAlgorithms = tlsCertificateCompressionAlgorithms.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q))).ToArray();

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.compress_certificate));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(1 + CertificateCompressionAlgorithms.Length))); // + 1 for size of CertificateCompressionAlgorithmsLength

    public byte CertificateCompressionAlgorithmsLength => (byte)CertificateCompressionAlgorithms.Length;

    // 2 bytes per item
    public byte[] CertificateCompressionAlgorithms { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(CertificateCompressionAlgorithmsLength);
        result.AddRange(CertificateCompressionAlgorithms);

        return [.. result];
    }
}