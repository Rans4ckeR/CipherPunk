namespace CipherPunk;

using System.Buffers.Binary;

public sealed record SupportedVersionsExtension : HandshakeExtension
{
    public SupportedVersionsExtension(TlsVersion[] tlsVersions)
    {
        SupportedVersions = tlsVersions.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q))).ToArray();
    }

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.supported_versions));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(1 + SupportedVersions.Length))); // + 1 for size of SupportedVersionsLength

    public byte SupportedVersionsLength => (byte)SupportedVersions.Length;

    // 2 bytes per item
    public byte[] SupportedVersions { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(SupportedVersionsLength);
        result.AddRange(SupportedVersions);

        return result.ToArray();
    }
}