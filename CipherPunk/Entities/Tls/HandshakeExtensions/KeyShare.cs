namespace CipherPunk;

using System.Buffers.Binary;

public sealed record KeyShare
{
    public KeyShare(TlsSupportedGroup tlsSupportedGroup, byte[] publicKey)
    {
        SupportedGroup = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)tlsSupportedGroup));
        PublicKey = publicKey;
    }

    // 2 bytes
    public byte[] SupportedGroup { get; }

    // 2 bytes
    public byte[] PublicKeyLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)PublicKey.Length));

    public byte[] PublicKey { get; }

    public byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(SupportedGroup);
        result.AddRange(PublicKeyLength);
        result.AddRange(PublicKey);

        return [.. result];
    }
}