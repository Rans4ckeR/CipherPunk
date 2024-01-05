namespace CipherPunk;

using System.Buffers.Binary;

public sealed record PreSharedKeysKeyExchangeModesExtension : HandshakeExtension
{
    public PreSharedKeysKeyExchangeModesExtension(TlsPreSharedKeysKeyExchangeMode[] tlsPreSharedKeysKeyExchangeModes)
        => PreSharedKeysKeyExchangeModes = tlsPreSharedKeysKeyExchangeModes.Cast<byte>().ToArray();

    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.psk_key_exchange_modes));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(1 + PreSharedKeysKeyExchangeModes.Length))); // + 1 for size of PreSharedKeysKeyExchangeModesLength

    public byte PreSharedKeysKeyExchangeModesLength => (byte)PreSharedKeysKeyExchangeModes.Length;

    // 1 byte per item
    public byte[] PreSharedKeysKeyExchangeModes { get; }

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);
        result.Add(PreSharedKeysKeyExchangeModesLength);
        result.AddRange(PreSharedKeysKeyExchangeModes);

        return [.. result];
    }
}