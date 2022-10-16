namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record SupportedGroupsHandshakeExtension : HandshakeExtension
{
    public SupportedGroupsHandshakeExtension(TlsSupportedGroup[] tlsSupportedGroups)
    {
        ExtensionTypeSupportedGroups = tlsSupportedGroups.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q))).ToArray();
    }

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.supported_groups));

    // 2 bytes
    public override byte[] ExtensionTypeLength { get => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeSupportedGroupsLength.Length + ExtensionTypeSupportedGroups.Length))); }

    // 2 bytes
    public byte[] ExtensionTypeSupportedGroupsLength { get => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ExtensionTypeSupportedGroups.Length)); }

    // 2 bytes per item
    public byte[] ExtensionTypeSupportedGroups { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(ExtensionTypeSupportedGroupsLength);
        result.AddRange(ExtensionTypeSupportedGroups);

        return result.ToArray();
    }
}