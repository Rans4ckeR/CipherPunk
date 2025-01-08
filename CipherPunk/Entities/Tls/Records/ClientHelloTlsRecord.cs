using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record ClientHelloTlsRecord : TlsRecord
{
    public ClientHelloTlsRecord(ReadOnlySpan<byte> data)
        : base(data)
    {
        HandshakeCipherSuites = [];
        HandshakeCompressionMethods = [];

        int index = TlsRecordHeader.Size + sizeof(byte) + HandshakeMessageLength.Length + HandshakeClientVersion.Length + HandshakeClientRandom.Length + sizeof(byte) + HandshakeSessionId.Length; // + 1 for TlsHandshakeHeaderMessageType, HandshakeSessionIdLength
        ushort handshakeCipherSuitesLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));

        HandshakeCipherSuites = data.TakeBytes(ref index, handshakeCipherSuitesLength);

        byte handshakeCompressionMethodsLength = data.TakeByte(ref index);

        HandshakeCompressionMethods = data.TakeBytes(ref index, handshakeCompressionMethodsLength);
        HandshakeExtensions = HandshakeExtension.GetExtensions(data[index..]);
    }

    public ClientHelloTlsRecord(
        string? serverName,
        TlsVersion tlsVersion,
        IReadOnlyCollection<TlsCipherSuite>? sslProviderCipherSuiteIds,
        IReadOnlyCollection<TlsCompressionMethodIdentifier>? tlsCompressionMethodIdentifiers,
        IReadOnlyCollection<TlsEllipticCurvesPointFormat>? tlsEllipticCurvesPointFormats,
        IReadOnlyCollection<TlsSignatureScheme>? tlsSignatureSchemes,
        IReadOnlyCollection<TlsSupportedGroup>? tlsSupportedGroups,
        IReadOnlyCollection<TlsVersion>? tlsVersions,
        IReadOnlyCollection<TlsPreSharedKeysKeyExchangeMode>? tlsPreSharedKeysKeyExchangeModes,
        KeyShare[]? keyShares,
        IReadOnlyCollection<TlsCertificateCompressionAlgorithm>? tlsCertificateCompressionAlgorithms)
        : base(tlsVersion, TlsContentType.handshake, TlsHandshakeType.client_hello)
    {
        HandshakeCipherSuites = sslProviderCipherSuiteIds?.Count > 0 ? [.. sslProviderCipherSuiteIds.SelectMany(static q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q)))] : [];
        HandshakeCompressionMethods = tlsCompressionMethodIdentifiers?.Count > 0 ? [.. tlsCompressionMethodIdentifiers.Cast<byte>()] : [];

        List<HandshakeExtension> handshakeExtensions =
        [
            new StatusRequestHandshakeExtension(),
            new RenegotiationInfoHandshakeExtension(),
            new SignedCertificateTimestampHandshakeExtension(),
            new SessionTicketExtension(),
            new EncryptThenMacExtension(),
            new ExtendedMasterSecretExtension()
        ];

        if (serverName is not null)
            handshakeExtensions.Add(new ServerNameHandshakeExtension(serverName));

        if (tlsEllipticCurvesPointFormats?.Count > 0)
            handshakeExtensions.Add(new EllipticCurvesPointFormatsHandshakeExtension(tlsEllipticCurvesPointFormats));

        if (tlsSignatureSchemes?.Count > 0)
            handshakeExtensions.Add(new SignatureAlgorithmsHandshakeExtension(tlsSignatureSchemes)); // "signature_algorithms" is REQUIRED for certificate authentication.

        if (tlsSupportedGroups?.Count > 0)
            handshakeExtensions.Add(new SupportedGroupsHandshakeExtension(tlsSupportedGroups)); // "supported_groups" is REQUIRED for ClientHello messages using DHE or ECDHE key exchange.

        if (tlsVersions?.Count > 0)
            handshakeExtensions.Add(new SupportedVersionsExtension(tlsVersions)); // "supported_versions" is REQUIRED for all ClientHello, ServerHello, and HelloRetryRequest messages.

        if (tlsPreSharedKeysKeyExchangeModes?.Count > 0)
            handshakeExtensions.Add(new PreSharedKeysKeyExchangeModesExtension(tlsPreSharedKeysKeyExchangeModes)); // "pre_shared_key" is REQUIRED for PSK key agreement.

        if (keyShares?.Length > 0)
            handshakeExtensions.Add(new KeyShareExtension(keyShares)); // "key_share" is REQUIRED for DHE or ECDHE key exchange.

        if (tlsCertificateCompressionAlgorithms?.Count > 0)
            handshakeExtensions.Add(new CompressCertificateHandshakeExtension(tlsCertificateCompressionAlgorithms));

        //// "psk_key_exchange_modes" is REQUIRED for PSK key agreement.

        const int paddingLength = 512;
        var padding = new PaddingHandshakeExtension(paddingLength - (sizeof(byte) + HandshakeMessageLength.Length + HandshakeMessageNumberOfBytes)); // + 1 for size of TlsHandshakeHeaderMessageType

        handshakeExtensions.Add(padding);

        HandshakeExtensions = [.. handshakeExtensions];
    }

    // 2 bytes
    public byte[] HandshakeCipherSuitesLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)HandshakeCipherSuites.Length));

    // 2 bytes per item
    public byte[] HandshakeCipherSuites { get; }

    public byte HandshakeCompressionMethodsLength => (byte)HandshakeCompressionMethods.Length;

    // 1 byte per item
    public byte[] HandshakeCompressionMethods { get; }

    protected override byte[] GetRecordTypeBytes()
    {
        var result = new List<byte>();

        result.AddRange(HandshakeCipherSuitesLength);
        result.AddRange(HandshakeCipherSuites);
        result.Add(HandshakeCompressionMethodsLength);
        result.AddRange(HandshakeCompressionMethods);

        return [.. result];
    }
}