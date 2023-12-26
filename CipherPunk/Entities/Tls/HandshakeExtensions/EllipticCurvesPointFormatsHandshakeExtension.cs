namespace CipherPunk;

using System.Buffers.Binary;

public sealed record EllipticCurvesPointFormatsHandshakeExtension : HandshakeExtension
{
    public EllipticCurvesPointFormatsHandshakeExtension(TlsEllipticCurvesPointFormat[] tlsEllipticCurvesPointFormats) => ExtensionTypeEcPointFormats = tlsEllipticCurvesPointFormats.Cast<byte>().ToArray();

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.ec_point_formats));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(ExtensionTypeEcPointFormats.Length + 1))); // + 1 for size of ExtensionTypeEcPointFormatsLength

    public byte ExtensionTypeEcPointFormatsLength => (byte)ExtensionTypeEcPointFormats.Length;

    // 1 byte per item
    public byte[] ExtensionTypeEcPointFormats { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(ExtensionTypeEcPointFormatsLength);
        result.AddRange(ExtensionTypeEcPointFormats);

        return [.. result];
    }
}