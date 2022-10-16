namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record PaddingHandshakeExtension : HandshakeExtension
{
    public PaddingHandshakeExtension(int paddingLength)
    {
        ExtensionTypePadding = new byte[paddingLength - ExtensionType.Length - 2]; // - 2 for ExtensionTypeLength
    }

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.padding));

    // 2 bytes
    public override byte[] ExtensionTypeLength { get => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ExtensionTypePadding.Length)); }

    // must contain all zeros
    public byte[] ExtensionTypePadding { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(ExtensionTypePadding);

        return result.ToArray();
    }
}