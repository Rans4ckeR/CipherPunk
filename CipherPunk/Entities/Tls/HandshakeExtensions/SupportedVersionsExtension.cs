using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record SupportedVersionsExtension : HandshakeExtension
{
    public SupportedVersionsExtension(IEnumerable<TlsVersion> tlsVersions)
        => SupportedVersions = [.. tlsVersions.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q)))];

    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.supported_versions));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(sizeof(byte) + SupportedVersions.Length))); // + 1 for size of SupportedVersionsLength

    public byte SupportedVersionsLength
        => (byte)SupportedVersions.Length;

    // 2 bytes per item
    public byte[] SupportedVersions { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(SupportedVersionsLength);
        result.AddRange(SupportedVersions);

        return [.. result];
    }
}