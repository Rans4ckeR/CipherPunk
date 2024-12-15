using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record SupportedGroupsHandshakeExtension : HandshakeExtension
{
    public SupportedGroupsHandshakeExtension(IEnumerable<TlsSupportedGroup> tlsSupportedGroups)
        => ExtensionTypeSupportedGroups = [.. tlsSupportedGroups.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q)))];

    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.supported_groups));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeSupportedGroupsLength.Length + ExtensionTypeSupportedGroups.Length)));

    // 2 bytes
    public byte[] ExtensionTypeSupportedGroupsLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ExtensionTypeSupportedGroups.Length));

    // 2 bytes per item
    public byte[] ExtensionTypeSupportedGroups { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(ExtensionTypeSupportedGroupsLength);
        result.AddRange(ExtensionTypeSupportedGroups);

        return [.. result];
    }
}