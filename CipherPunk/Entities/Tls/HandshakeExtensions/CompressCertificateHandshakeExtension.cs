﻿using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record CompressCertificateHandshakeExtension : HandshakeExtension
{
    public CompressCertificateHandshakeExtension(IEnumerable<TlsCertificateCompressionAlgorithm> tlsCertificateCompressionAlgorithms)
        => CertificateCompressionAlgorithms = [.. tlsCertificateCompressionAlgorithms.SelectMany(static q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q)))];

    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.compress_certificate));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(sizeof(byte) + CertificateCompressionAlgorithms.Length))); // + 1 for size of CertificateCompressionAlgorithmsLength

    public byte CertificateCompressionAlgorithmsLength
        => (byte)CertificateCompressionAlgorithms.Length;

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