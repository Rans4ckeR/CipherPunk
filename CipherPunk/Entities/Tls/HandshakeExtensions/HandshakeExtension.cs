using System.Buffers.Binary;

namespace CipherPunk;

internal abstract record HandshakeExtension
{
    public abstract byte[] ExtensionType { get; }

    public abstract byte[] ExtensionTypeLength { get; }

    public abstract byte[] GetBytes();

    public static IReadOnlyCollection<HandshakeExtension> GetExtensions(ReadOnlySpan<byte> data)
    {
        var handshakeExtensions = new List<HandshakeExtension>();
        int index = 0;
        ////ushort handshakeExtensionsLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));

        while (index < data.Length)
        {
            var tlsExtensionType = (TlsExtensionType)BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
            ushort tlsExtensionLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
            int extensionEndIndex;

            switch (tlsExtensionType)
            {
                case TlsExtensionType.key_share:
                    extensionEndIndex = index + tlsExtensionLength;
                    var keyShares = new List<KeyShare>();

                    while (index != extensionEndIndex)
                    {
                        var tlsSupportedGroup = (TlsSupportedGroup)BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
                        ushort extensionLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
                        byte[] publicKey = data.TakeBytes(ref index, extensionLength);

                        keyShares.Add(new(tlsSupportedGroup, publicKey));
                    }

                    handshakeExtensions.Add(new KeyShareExtension([.. keyShares]));
                    break;
                case TlsExtensionType.supported_versions:
                    extensionEndIndex = index + tlsExtensionLength;
                    var tlsVersions = new List<TlsVersion>();

                    while (index != extensionEndIndex)
                    {
                        var tlsVersion = (TlsVersion)BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));

                        tlsVersions.Add(tlsVersion);
                    }

                    handshakeExtensions.Add(new SupportedVersionsExtension([.. tlsVersions]));
                    break;
                default:
                    index += tlsExtensionLength;
                    break;
            }
        }

        return [.. handshakeExtensions];
    }
}