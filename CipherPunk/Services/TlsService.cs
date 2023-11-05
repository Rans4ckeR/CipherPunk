namespace CipherPunk;

using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

internal sealed class TlsService : ITlsService
{
    public WindowsSchannelVersion GetWindowsSchannelVersion()
    {
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22631)) // Windows11v23H2
            return WindowsSchannelVersion.Windows11V22H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621)) // Windows11v22H2
            return WindowsSchannelVersion.Windows11V22H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) // Windows11v21H2
            return WindowsSchannelVersion.Windows11;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348)) // WindowsServer2022
            return WindowsSchannelVersion.WindowsServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19045)) // Windows10v22H2
            return WindowsSchannelVersion.Windows10V22H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19044)) // Windows10v21H2
            return WindowsSchannelVersion.Windows10V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19043)) // Windows10v21H1
            return WindowsSchannelVersion.Windows10V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19042)) // Windows10v20H2
            return WindowsSchannelVersion.Windows10V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) // Windows10v2004
            return WindowsSchannelVersion.Windows10V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18363)) // Windows10v1909
            return WindowsSchannelVersion.Windows10V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362)) // Windows10v1903
            return WindowsSchannelVersion.Windows10V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) // Windows10v1809OrServer2019
            return WindowsSchannelVersion.Windows10V1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17134)) // Windows10v1803
            return WindowsSchannelVersion.Windows10V1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 16299))
            return WindowsSchannelVersion.Windows10V1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 15063))
            return WindowsSchannelVersion.Windows10V1703;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 14393))
            return WindowsSchannelVersion.Windows10V1607OrServer2016;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
            return WindowsSchannelVersion.Windows10V1511;

        if (OperatingSystem.IsWindowsVersionAtLeast(10))
            return WindowsSchannelVersion.Windows10V1507;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3))
            return WindowsSchannelVersion.Windows81OrServer2012R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            return WindowsSchannelVersion.Windows8OrServer2012;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 1))
            return WindowsSchannelVersion.Windows7OrServer2008R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6))
            return WindowsSchannelVersion.WindowsVistaOrServer2008;

        throw new SchannelServiceException(FormattableString.Invariant($"Unknown Windows version {Environment.OSVersion.Version}."));
    }

    public async ValueTask<List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, TlsVersion tlsVersion, CancellationToken cancellationToken = default)
    {
        IPEndPoint ipEndPoint = await GetIpEndPointAsync(hostName, cancellationToken);

        ipEndPoint.Port = port;

        return await GetRemoteServerCipherSuitesAsync(ipEndPoint, hostName, tlsVersion, cancellationToken);
    }

    public async ValueTask<List<(TlsVersion TlsVersion, List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, CancellationToken cancellationToken = default)
    {
        IPEndPoint ipEndPoint = await GetIpEndPointAsync(hostName, cancellationToken);

        ipEndPoint.Port = port;

        var result = new List<(TlsVersion TlsVersion, List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)>();

        foreach (TlsVersion sslProviderProtocolId in Enum.GetValues<TlsVersion>())
        {
            List<(uint CipherSuiteId, bool Supported, string? ErrorReason)> sslProviderProtocolIdResult = await GetRemoteServerCipherSuitesAsync(ipEndPoint, hostName, sslProviderProtocolId, cancellationToken);

            result.Add((sslProviderProtocolId, sslProviderProtocolIdResult));
        }

        return result;
    }

    private static async ValueTask<IPEndPoint> GetIpEndPointAsync(string hostName, CancellationToken cancellationToken)
    {
        IPAddress[] ipAddresses = await Dns.GetHostAddressesAsync(hostName, cancellationToken);

        return new(ipAddresses.First(q => (Socket.OSSupportsIPv6 && q.AddressFamily is AddressFamily.InterNetworkV6) || q.AddressFamily is AddressFamily.InterNetwork), 443);
    }

    private static async ValueTask<List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>> GetRemoteServerCipherSuitesAsync(EndPoint endpoint, string hostName, TlsVersion tlsVersion, CancellationToken cancellationToken)
    {
#pragma warning disable SA1010 // Opening square brackets should be spaced correctly
        TlsCompressionMethodIdentifier[] tlsCompressionMethodIdentifiers = [TlsCompressionMethodIdentifier.NULL];
#pragma warning restore SA1010 // Opening square brackets should be spaced correctly
        TlsEllipticCurvesPointFormat[] tlsEllipticCurvesPointFormats = Enum.GetValues<TlsEllipticCurvesPointFormat>();
        TlsSignatureScheme[] tlsSignatureSchemes = Enum.GetValues<TlsSignatureScheme>();
        TlsSupportedGroup[] tlsSupportedGroups = Enum.GetValues<TlsSupportedGroup>();
        TlsPreSharedKeysKeyExchangeMode[] tlsPreSharedKeysKeyExchangeModes = Enum.GetValues<TlsPreSharedKeysKeyExchangeMode>();
        TlsCertificateCompressionAlgorithm[] tlsCertificateCompressionAlgorithms = Enum.GetValues<TlsCertificateCompressionAlgorithm>();
        byte[] clientPublicKey = new byte[32];

        new Random().NextBytes(clientPublicKey);

        var keyShares = new KeyShare[] { new(TlsSupportedGroup.x25519, clientPublicKey) };
        uint[] sslProviderCipherSuiteIds = tlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION
            ? Enum.GetValuesAsUnderlyingType<SslCipherSuite>().Cast<uint>().ToArray()
            : Enum.GetValuesAsUnderlyingType<TlsCipherSuite>().Cast<ushort>().Select(Convert.ToUInt32).ToArray();

        return (await Task.WhenAll(sslProviderCipherSuiteIds.Select(q => SendClientHelloAsync(endpoint, hostName, tlsVersion, tlsCompressionMethodIdentifiers, tlsEllipticCurvesPointFormats, tlsSignatureSchemes, tlsSupportedGroups, tlsPreSharedKeysKeyExchangeModes, keyShares, tlsCertificateCompressionAlgorithms, q, cancellationToken).AsTask()))).ToList();
    }

    private static async ValueTask<(uint CipherSuiteId, bool Supported, string? ErrorReason)> SendClientHelloAsync(
        EndPoint endpoint,
        string hostName,
        TlsVersion tlsVersion,
        TlsCompressionMethodIdentifier[] tlsCompressionMethodIdentifiers,
        TlsEllipticCurvesPointFormat[] tlsEllipticCurvesPointFormats,
        TlsSignatureScheme[] tlsSignatureSchemes,
        TlsSupportedGroup[] tlsSupportedGroups,
        TlsPreSharedKeysKeyExchangeMode[] tlsPreSharedKeysKeyExchangeModes,
        KeyShare[] keyShares,
        TlsCertificateCompressionAlgorithm[] tlsCertificateCompressionAlgorithms,
        uint sslProviderCipherSuiteId,
        CancellationToken cancellationToken)
    {
        await Task.Delay(Random.Shared.Next(1, 10000), cancellationToken);

        byte[] clientHelloBytes;

        if (tlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION)
        {
            var ssl2ClientHelloRecord = new Ssl2ClientHelloRecord([(SslCipherSuite)sslProviderCipherSuiteId]);

            clientHelloBytes = ssl2ClientHelloRecord.GetBytes();
        }
        else
        {
            var clientHelloTlsRecord = new ClientHelloTlsRecord(
                IPAddress.TryParse(hostName, out _) ? null : hostName,
                tlsVersion,
                [(TlsCipherSuite)sslProviderCipherSuiteId],
                tlsCompressionMethodIdentifiers,
                tlsEllipticCurvesPointFormats,
                tlsSignatureSchemes,
                tlsSupportedGroups,
                [tlsVersion],
                tlsPreSharedKeysKeyExchangeModes,
                keyShares,
                tlsCertificateCompressionAlgorithms);

            clientHelloBytes = clientHelloTlsRecord.GetBytes();
        }

        Memory<byte> responseBytes;

        try
        {
            responseBytes = await SendClientHelloAsync(clientHelloBytes, endpoint, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (sslProviderCipherSuiteId, false, "Timed out");
        }
        catch (SocketException ex)
        {
            return (sslProviderCipherSuiteId, false, FormattableString.CurrentCulture($"Connection refused with {nameof(ex.ErrorCode)} {ex.ErrorCode}"));
        }

        if (responseBytes.Span.IsEmpty)
            return (sslProviderCipherSuiteId, false, "Empty server response");

        if (IsSsl2Response(responseBytes))
        {
            var ssl2ServerHelloRecord = new Ssl2ServerHelloRecord(responseBytes.Span);

            return (sslProviderCipherSuiteId, ssl2ServerHelloRecord.CipherSpecs.Length > 0, null);
        }

        TlsRecord tlsRecord;

        try
        {
            tlsRecord = TlsRecord.Parse(responseBytes.Span);
        }
        catch (ArgumentOutOfRangeException ex)
        {
            return (sslProviderCipherSuiteId, false, ex.Message);
        }

        switch ((TlsContentType?)tlsRecord.TlsRecordHeader.TlsRecordContentType)
        {
            case TlsContentType.alert:
                var alertRecord = (AlertTlsRecord)tlsRecord;

                return (sslProviderCipherSuiteId, false, FormattableString.CurrentCulture($"TLS Alert: {(TlsAlertDescription)alertRecord.Description}"));
            case TlsContentType.handshake:
                var serverHandshakeTlsVersion = (TlsVersion)BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(tlsRecord.HandshakeClientVersion));

                byte[]? supportedVersions = ((ServerHelloTlsRecord)tlsRecord).HandshakeExtensions.OfType<SupportedVersionsExtension>().SingleOrDefault()?.SupportedVersions;
                var tlsVersions = new List<TlsVersion>();

                if (supportedVersions?.Length > 0)
                {
                    int index = 0;

                    while (index < supportedVersions.Length)
                    {
                        tlsVersions.Add((TlsVersion)BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(supportedVersions.Skip(index).Take(2).ToArray())));

                        index += 2;
                    }
                }

                if ((tlsVersion is TlsVersion.TLS1_3_PROTOCOL_VERSION && (serverHandshakeTlsVersion is not TlsVersion.TLS1_2_PROTOCOL_VERSION || !tlsVersions.Contains(tlsVersion)))
                    || (tlsVersion is not TlsVersion.TLS1_3_PROTOCOL_VERSION && serverHandshakeTlsVersion != tlsVersion))
                {
                    return (sslProviderCipherSuiteId, false, FormattableString.CurrentCulture($"TLS downgrade to {serverHandshakeTlsVersion}"));
                }

                return (sslProviderCipherSuiteId, true, null);
            default:
                throw new ArgumentOutOfRangeException(nameof(tlsRecord.TlsRecordHeader.TlsRecordContentType), (TlsContentType?)tlsRecord.TlsRecordHeader.TlsRecordContentType, null);
        }
    }

    private static bool IsSsl2Response(Memory<byte> responseBytes)
    {
        // https://www.rfc-editor.org/rfc/rfc2246#appendix-E
        // E.1. Version 2 client hello
        return (responseBytes.Span[0] & 0x80) is 0x80;
    }

    private static async ValueTask<Memory<byte>> SendClientHelloAsync(Memory<byte> clientHelloBytes, EndPoint endPoint, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> memoryOwner = MemoryPool<byte>.Shared.Rent(8192);
        Memory<byte> buffer = memoryOwner.Memory[..8192];

        // https://tls12.xargs.org/
        // https://wiki.osdev.org/TLS_Handshake
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        CancellationToken timeoutCancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, new CancellationTokenSource(10000).Token).Token;

        await socket.ConnectAsync(endPoint, timeoutCancellationToken);

        _ = await socket.SendAsync(clientHelloBytes, timeoutCancellationToken);

        int receivedBytes = await socket.ReceiveAsync(buffer, timeoutCancellationToken);

        return buffer[..receivedBytes];
    }
}