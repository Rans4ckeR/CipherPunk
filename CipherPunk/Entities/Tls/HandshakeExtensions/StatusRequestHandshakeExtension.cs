﻿using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record StatusRequestHandshakeExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.status_request));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeStatusRequestResponderIdLength.Length + ExtensionTypeStatusRequestRequestExtensionLength.Length + sizeof(byte)))); // + 1 for size of ExtensionTypeStatusRequestType

    public static byte ExtensionTypeStatusRequestType
        => 0x01; // 0x00: certificate status type OCSP

    // 2 bytes
    public static byte[] ExtensionTypeStatusRequestResponderIdLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0));

    // 2 bytes
    public static byte[] ExtensionTypeStatusRequestRequestExtensionLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0));

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(ExtensionTypeStatusRequestType);
        result.AddRange(ExtensionTypeStatusRequestResponderIdLength);
        result.AddRange(ExtensionTypeStatusRequestRequestExtensionLength);

        return [.. result];
    }
}