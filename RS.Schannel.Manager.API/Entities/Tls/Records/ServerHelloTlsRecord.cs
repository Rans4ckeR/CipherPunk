namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;
using Windows.Win32;

public sealed record ServerHelloTlsRecord : TlsRecord
{
    public ServerHelloTlsRecord(ReadOnlySpan<byte> data)
        : base(data)
    {
        HandshakeCipherSuite = Array.Empty<byte>();
        int index = TlsRecordHeader.Size + 1 + HandshakeMessageLength.Length + HandshakeClientVersion.Length + HandshakeClientRandom.Length + 1 + HandshakeSessionId.Length; // + 1 for TlsHandshakeHeaderMessageType, HandshakeSessionIdLength

        HandshakeCipherSuite = data.TakeBytes(ref index, 2);
        HandshakeCompressionMethod = data.TakeByte(ref index);

        ushort handshakeExtensionsLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));

        HandshakeExtensions = HandshakeExtension.GetExtensions(data[index..(index + handshakeExtensionsLength)]);
    }

    ////public ServerHelloTlsRecord(string serverName, TlsVersion tlsVersion, SslProviderCipherSuiteId sslProviderCipherSuiteId, TlsCompressionMethodIdentifier tlsCompressionMethodIdentifier, TlsEllipticCurvesPointFormat[]? tlsEllipticCurvesPointFormats, TlsSignatureScheme[]? tlsSignatureSchemes, TlsSupportedGroup[]? tlsSupportedGroups, TlsVersion[]? tlsVersions, TlsPreSharedKeysKeyExchangeMode[]? tlsPreSharedKeysKeyExchangeModes, KeyShare[]? keyShares)
    ////    : base(tlsVersion, TlsContentType.handshake, TlsHandshakeType.client_hello)
    ////{
    ////    HandshakeCipherSuite = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)sslProviderCipherSuiteId));
    ////    HandshakeCompressionMethod = (byte)tlsCompressionMethodIdentifier;

    ////    HandshakeExtensions.AddRange(new HandshakeExtension[]
    ////    {
    ////        new ServerNameHandshakeExtension(serverName),
    ////        new StatusRequestHandshakeExtension(),
    ////        new RenegotiationInfoHandshakeExtension(),
    ////        new SignedCertificateTimestampHandshakeExtension(),
    ////        new SessionTicketExtension(),
    ////        new EncryptThenMacExtension(),
    ////        new ExtendedMasterSecretExtension()
    ////    });

    ////    if (tlsEllipticCurvesPointFormats?.Any() ?? false)
    ////        HandshakeExtensions.Add(new EllipticCurvesPointFormatsHandshakeExtension(tlsEllipticCurvesPointFormats));

    ////    if (tlsSignatureSchemes?.Any() ?? false)
    ////        HandshakeExtensions.Add(new SignatureAlgorithmsHandshakeExtension(tlsSignatureSchemes));

    ////    if (tlsSupportedGroups?.Any() ?? false)
    ////        HandshakeExtensions.Add(new SupportedGroupsHandshakeExtension(tlsSupportedGroups));

    ////    if (tlsVersions?.Any() ?? false)
    ////        HandshakeExtensions.Add(new SupportedVersionsExtension(tlsVersions));

    ////    if (tlsPreSharedKeysKeyExchangeModes?.Any() ?? false)
    ////        HandshakeExtensions.Add(new PreSharedKeysKeyExchangeModesExtension(tlsPreSharedKeysKeyExchangeModes));

    ////    if (keyShares?.Any() ?? false)
    ////        HandshakeExtensions.Add(new KeyShareExtension(keyShares));

    ////    //var padding = new PaddingHandshakeExtension(512 + TlsRecordVersion.Length + TlsRecordLength.Length - (1 + HandshakeMessageLength.Length + HandshakeMessageNumberOfBytes) - 4);
    ////    ////var padding = new PaddingHandshakeExtension(512 - 1 - TlsRecordVersion.Length - TlsRecordLength.Length - 1 - HandshakeMessageNumberOfBytes); // - 1 for TlsRecordContentType, - 1 for TlsHandshakeHeaderMessageType

    ////    //HandshakeExtensions.Add(padding);
    ////}

    // 2 bytes
    public byte[] HandshakeCipherSuite { get; }

    // 1 byte
    public byte HandshakeCompressionMethod { get; }

    public static implicit operator TlsServerHello(ServerHelloTlsRecord serverHelloTlsRecord)
    {
        return new((SslProviderCipherSuiteId)BitConverter.ToUInt16(serverHelloTlsRecord.HandshakeCipherSuite), (TlsCompressionMethodIdentifier)serverHelloTlsRecord.HandshakeCompressionMethod);
    }

    protected override byte[] GetRecordTypeBytes()
    {
        var result = new List<byte>();

        result.AddRange(HandshakeCipherSuite);
        result.Add(HandshakeCompressionMethod);

        return result.ToArray();
    }
}