namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record KeyShareExtension : HandshakeExtension
{
    public KeyShareExtension(KeyShare[] keyShares)
    {
        KeyShares = keyShares;
    }

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.key_share));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(KeyShareLength.Length + KeyShares.SelectMany(q => q.GetBytes()).Count())));

    // 2 bytes
    public byte[] KeyShareLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)KeyShares.SelectMany(q => q.GetBytes()).Count()));

    public KeyShare[] KeyShares { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.AddRange(KeyShareLength);
        result.AddRange(KeyShares.SelectMany(q => q.GetBytes()));

        return result.ToArray();
    }
}