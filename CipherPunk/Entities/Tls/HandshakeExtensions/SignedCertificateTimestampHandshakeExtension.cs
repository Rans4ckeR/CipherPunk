﻿using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record SignedCertificateTimestampHandshakeExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.signed_certificate_timestamp));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0)); // length 0

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);

        return [.. result];
    }
}