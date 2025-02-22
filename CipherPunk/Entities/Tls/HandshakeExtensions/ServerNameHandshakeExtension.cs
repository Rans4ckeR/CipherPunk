﻿using System.Buffers.Binary;
using System.Text;

namespace CipherPunk;

internal sealed record ServerNameHandshakeExtension : HandshakeExtension
{
    public ServerNameHandshakeExtension(string serverName)
        => ExtensionTypeServerName = Encoding.Default.GetBytes(serverName);

    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.server_name));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeServerName.Length + ExtensionTypeEntryLength.Length + sizeof(byte) + 2))); // + 1 for size of ExtensionTypeServerNameEntryType, + 2 for size of ExtensionTypeLength

    // 2 bytes
    public byte[] ExtensionTypeEntryLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeServerName.Length + ExtensionTypeServerNameLength.Length + sizeof(byte)))); // + 1 for size of ExtensionTypeServerNameEntryType

    public static byte ExtensionTypeServerNameEntryType
        => 0x00; // 0x00: DNS hostname

    // 2 bytes
    public byte[] ExtensionTypeServerNameLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ExtensionTypeServerName.Length));

    public byte[] ExtensionTypeServerName { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(ExtensionTypeEntryLength);
        result.Add(ExtensionTypeServerNameEntryType);
        result.AddRange(ExtensionTypeServerNameLength);
        result.AddRange(ExtensionTypeServerName);

        return [.. result];
    }
}