﻿namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record ClientHelloTlsRecord : TlsRecord
{
    public ClientHelloTlsRecord(ReadOnlySpan<byte> data)
        : base(data)
    {
        HandshakeCipherSuites = Array.Empty<byte>();
        HandshakeCompressionMethods = Array.Empty<byte>();

        int index = TlsRecordHeader.Size + 1 + HandshakeMessageLength.Length + HandshakeClientVersion.Length + HandshakeClientRandom.Length + 1 + HandshakeSessionId.Length; // + 1 for TlsHandshakeHeaderMessageType, HandshakeSessionIdLength
        ushort handshakeCipherSuitesLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));

        HandshakeCipherSuites = data.TakeBytes(ref index, handshakeCipherSuitesLength);

        byte handshakeCompressionMethodsLength = data.TakeByte(ref index);

        HandshakeCompressionMethods = data.TakeBytes(ref index, handshakeCompressionMethodsLength);
        HandshakeExtensions = HandshakeExtension.GetExtensions(data[index..]);
    }

    public ClientHelloTlsRecord(string serverName, TlsVersion tlsVersion, TlsCipherSuites[]? sslProviderCipherSuiteIds, TlsCompressionMethodIdentifier[]? tlsCompressionMethodIdentifiers, TlsEllipticCurvesPointFormat[]? tlsEllipticCurvesPointFormats, TlsSignatureScheme[]? tlsSignatureSchemes, TlsSupportedGroup[]? tlsSupportedGroups, TlsVersion[]? tlsVersions, TlsPreSharedKeysKeyExchangeMode[]? tlsPreSharedKeysKeyExchangeModes, KeyShare[]? keyShares)
        : base(tlsVersion, TlsContentType.handshake, TlsHandshakeType.client_hello)
    {
        HandshakeCipherSuites = sslProviderCipherSuiteIds?.Any() ?? false
            ? sslProviderCipherSuiteIds.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)q))).ToArray()
            : Array.Empty<byte>();

        HandshakeCompressionMethods = tlsCompressionMethodIdentifiers?.Any() ?? false
            ? tlsCompressionMethodIdentifiers.Cast<byte>().ToArray()
            : Array.Empty<byte>();

        HandshakeExtensions.AddRange(new HandshakeExtension[]
        {
            new ServerNameHandshakeExtension(serverName),
            new StatusRequestHandshakeExtension(),
            new RenegotiationInfoHandshakeExtension(),
            new SignedCertificateTimestampHandshakeExtension(),
            new SessionTicketExtension(),
            new EncryptThenMacExtension(),
            new ExtendedMasterSecretExtension()
        });

        if (tlsEllipticCurvesPointFormats?.Any() ?? false)
            HandshakeExtensions.Add(new EllipticCurvesPointFormatsHandshakeExtension(tlsEllipticCurvesPointFormats));

        if (tlsSignatureSchemes?.Any() ?? false)
            HandshakeExtensions.Add(new SignatureAlgorithmsHandshakeExtension(tlsSignatureSchemes));

        if (tlsSupportedGroups?.Any() ?? false)
            HandshakeExtensions.Add(new SupportedGroupsHandshakeExtension(tlsSupportedGroups));

        if (tlsVersions?.Any() ?? false)
            HandshakeExtensions.Add(new SupportedVersionsExtension(tlsVersions));

        if (tlsPreSharedKeysKeyExchangeModes?.Any() ?? false)
            HandshakeExtensions.Add(new PreSharedKeysKeyExchangeModesExtension(tlsPreSharedKeysKeyExchangeModes));

        if (keyShares?.Any() ?? false)
            HandshakeExtensions.Add(new KeyShareExtension(keyShares));

        var padding = new PaddingHandshakeExtension(512 - (1 + HandshakeMessageLength.Length + HandshakeMessageNumberOfBytes)); // + 1 for size of TlsHandshakeHeaderMessageType

        HandshakeExtensions.Add(padding);
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

        return result.ToArray();
    }
}