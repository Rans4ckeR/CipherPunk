using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record PreSharedKeysKeyExchangeModesExtension : HandshakeExtension
{
    public PreSharedKeysKeyExchangeModesExtension(IEnumerable<TlsPreSharedKeysKeyExchangeMode> tlsPreSharedKeysKeyExchangeModes)
        => PreSharedKeysKeyExchangeModes = [.. tlsPreSharedKeysKeyExchangeModes.Cast<byte>()];

    // 2 bytes
    public override byte[] ExtensionType
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.psk_key_exchange_modes));

    // 2 bytes
    public override byte[] ExtensionTypeLength
        => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(sizeof(byte) + PreSharedKeysKeyExchangeModes.Length))); // + 1 for size of PreSharedKeysKeyExchangeModesLength

    public byte PreSharedKeysKeyExchangeModesLength
        => (byte)PreSharedKeysKeyExchangeModes.Length;

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