namespace RS.Schannel.Manager.API;

using System.Buffers;
using System.Net;
using System.Net.Sockets;

internal sealed class TlsService : ITlsService
{
    public WindowsSchannelVersion GetWindowsSchannelVersion()
    {
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621)) // Windows11v22H2
            return WindowsSchannelVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) // Windows11v21H2
            return WindowsSchannelVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348)) // WindowsServer2022
            return WindowsSchannelVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19045)) // Windows10v22H2
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19044)) // Windows10v21H2
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19043)) // Windows10v21H1
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19042)) // Windows10v20H2
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) // Windows10v2004
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18363)) // Windows10v1909
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362)) // Windows10v1903
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) // Windows10v1809OrServer2019
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17134)) // Windows10v1803
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 16299))
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 15063))
            return WindowsSchannelVersion.Windows10v1703;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 14393))
            return WindowsSchannelVersion.Windows10v1607OrServer2016;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
            return WindowsSchannelVersion.Windows10v1511;

        if (OperatingSystem.IsWindowsVersionAtLeast(10))
            return WindowsSchannelVersion.Windows10v1507;

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

    public async Task<List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>> GetRemoteServerCipherSuitesAsync(string hostName, TlsVersion tlsVersion, CancellationToken cancellationToken)
    {
        IPEndPoint ipEndPoint = await GetIpEndPointAsync(hostName, cancellationToken);

        return await GetRemoteServerCipherSuitesAsync(ipEndPoint, hostName, tlsVersion, cancellationToken);
    }

    public async Task<List<(TlsVersion, List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>?)>> GetRemoteServerCipherSuitesAsync(string hostName, CancellationToken cancellationToken)
    {
        IPEndPoint ipEndPoint = await GetIpEndPointAsync(hostName, cancellationToken);
        var result = new List<(TlsVersion, List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>?)>();

        foreach (TlsVersion sslProviderProtocolId in Enum.GetValues<TlsVersion>())
        {
            List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)> sslProviderProtocolIdResult = await GetRemoteServerCipherSuitesAsync(ipEndPoint, hostName, sslProviderProtocolId, cancellationToken);

            result.Add((sslProviderProtocolId, sslProviderProtocolIdResult));
        }

        return result;
    }

    private static async Task<IPEndPoint> GetIpEndPointAsync(string hostName, CancellationToken cancellationToken)
    {
        IPAddress[] ipAddresses = await Dns.GetHostAddressesAsync(hostName, cancellationToken);

        return new IPEndPoint(ipAddresses.First(q => (Socket.OSSupportsIPv6 && q.AddressFamily is AddressFamily.InterNetworkV6) || q.AddressFamily is AddressFamily.InterNetwork), 443);
    }

    private static async Task<List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>> GetRemoteServerCipherSuitesAsync(IPEndPoint ipEndpoint, string hostName, TlsVersion tlsVersion, CancellationToken cancellationToken)
    {
        //TlsCompressionMethodIdentifier[] tlsCompressionMethodIdentifiers = tlsVersion is TlsVersion.TLS1_3_PROTOCOL_VERSION ? new[] { TlsCompressionMethodIdentifier.NULL } : Enum.GetValues<TlsCompressionMethodIdentifier>();
        TlsCompressionMethodIdentifier[] tlsCompressionMethodIdentifiers = { TlsCompressionMethodIdentifier.NULL };
        TlsEllipticCurvesPointFormat[] tlsEllipticCurvesPointFormats = Enum.GetValues<TlsEllipticCurvesPointFormat>();
        TlsSignatureScheme[] tlsSignatureSchemes = Enum.GetValues<TlsSignatureScheme>();
        TlsSupportedGroup[] tlsSupportedGroups = Enum.GetValues<TlsSupportedGroup>();
        TlsPreSharedKeysKeyExchangeMode[] tlsPreSharedKeysKeyExchangeModes = Enum.GetValues<TlsPreSharedKeysKeyExchangeMode>();
        byte[] clientPublicKey = new byte[32];

        new Random().NextBytes(clientPublicKey);

        var keyShares = new KeyShare[] { new(TlsSupportedGroup.x25519, clientPublicKey) };
        var results = new List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>();
        uint[] sslProviderCipherSuiteIds = tlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION
            ? Enum.GetValuesAsUnderlyingType<SslCipherSuites>().Cast<uint>().ToArray()
            : Enum.GetValuesAsUnderlyingType<TlsCipherSuites>().Cast<ushort>().Select(Convert.ToUInt32).ToArray();

        // https://www.rfc-editor.org/rfc/rfc2246#appendix-E
        // E.1. Version 2 client hello
        foreach (uint sslProviderCipherSuiteId in sslProviderCipherSuiteIds)
        {
            byte[] clientHelloBytes;

            if (tlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION)
            {
                var ssl2ClientHelloRecord = new Ssl2ClientHelloRecord(new[] { (SslCipherSuites)sslProviderCipherSuiteId });

                clientHelloBytes = ssl2ClientHelloRecord.GetBytes();
            }
            else
            {
                var clientHelloTlsRecord = new ClientHelloTlsRecord(hostName, tlsVersion, new[] { (TlsCipherSuites)sslProviderCipherSuiteId }, tlsCompressionMethodIdentifiers, tlsEllipticCurvesPointFormats, tlsSignatureSchemes, tlsSupportedGroups, new[] { tlsVersion }, tlsPreSharedKeysKeyExchangeModes, keyShares);

                clientHelloBytes = clientHelloTlsRecord.GetBytes();
            }

            Memory<byte> responseBytes = default;

            try
            {
                responseBytes = await SendClientHelloAsync(cancellationToken, clientHelloBytes, ipEndpoint);
            }
            catch (OperationCanceledException)
            {
            }
            catch (SocketException)
            {
            }

            if (!responseBytes.Span.IsEmpty && IsSsl2Response(responseBytes))
            {
                Ssl2ServerHelloRecord? ssl2ServerHelloRecord = responseBytes.Span.IsEmpty ? null : new Ssl2ServerHelloRecord(responseBytes.Span);

                results.Add((sslProviderCipherSuiteId, ssl2ServerHelloRecord?.CipherSpecs.Any() ?? false, null));
            }
            else
            {
                TlsRecord? tlsRecord = responseBytes.Span.IsEmpty ? null : TlsRecord.Parse(responseBytes.Span);

                switch ((TlsContentType?)tlsRecord?.TlsRecordHeader.TlsRecordContentType)
                {
                    case TlsContentType.alert:
                        var alertRecord = (AlertTlsRecord)tlsRecord;

                        results.Add((sslProviderCipherSuiteId, false, alertRecord));
                        break;
                    case null:
                        results.Add((sslProviderCipherSuiteId, false, null));
                        break;
                    case TlsContentType.handshake:
                        results.Add((sslProviderCipherSuiteId, true, null));
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
        }

        return results;
    }

    private static bool IsSsl2Response(Memory<byte> responseBytes)
    {
        return (responseBytes.Span[0] & 0x80) == 0x80;
    }

    ////private async Task GetRemoteServerCipherSuitesAsync1(string hostName, CancellationToken cancellationToken)
    ////{
    ////    IPAddress[] ipAddresses = await Dns.GetHostAddressesAsync(hostName, cancellationToken);
    ////    using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);

    ////    await socket.ConnectAsync(new IPEndPoint(ipAddresses.First(), 443), cancellationToken);

    ////    SslProviderCipherSuiteId[] sslProviderCipherSuiteIds =
    ////        {
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_MD5,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_EXPORT_WITH_RC4_40_MD5,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_MD5,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_DES_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_DES_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA,

    ////            // TLS 1.2
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA256,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_GCM_SHA256,
    ////            SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_GCM_SHA384,
    ////            SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    ////            SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,

    ////            // PSK
    ////            SslProviderCipherSuiteId.TLS_PSK_WITH_AES_128_GCM_SHA256,
    ////            SslProviderCipherSuiteId.TLS_PSK_WITH_AES_256_GCM_SHA384,
    ////            SslProviderCipherSuiteId.TLS_PSK_WITH_AES_128_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_PSK_WITH_AES_256_CBC_SHA384,
    ////            SslProviderCipherSuiteId.TLS_PSK_WITH_NULL_SHA256,
    ////            SslProviderCipherSuiteId.TLS_PSK_WITH_NULL_SHA384,

    ////            SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,

    ////            // TLS 1.2
    ////            SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ////            SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

    ////            // TLS 1.3
    ////            SslProviderCipherSuiteId.TLS_AES_128_GCM_SHA256,
    ////            SslProviderCipherSuiteId.TLS_AES_256_GCM_SHA384,
    ////            SslProviderCipherSuiteId.TLS_CHACHA20_POLY1305_SHA256
    ////        };

    ////    TlsCompressionMethodIdentifier[] tlsCompressionMethodIdentifiers =
    ////        {
    ////            TlsCompressionMethodIdentifier.NULL
    ////        };

    ////    TlsEllipticCurvesPointFormat[] tlsEllipticCurvesPointFormats =
    ////        {
    ////            TlsEllipticCurvesPointFormat.uncompressed,
    ////            TlsEllipticCurvesPointFormat.ansiX962_compressed_prime,
    ////            TlsEllipticCurvesPointFormat.ansiX962_compressed_char2
    ////        };

    ////    TlsSignatureScheme[] tlsSignatureSchemes =
    ////        {
    ////            TlsSignatureScheme.rsa_pkcs1_sha1,
    ////            TlsSignatureScheme.ecdsa_sha1,
    ////            TlsSignatureScheme.rsa_pkcs1_sha256,
    ////            TlsSignatureScheme.ecdsa_secp256r1_sha256,
    ////            TlsSignatureScheme.rsa_pkcs1_sha256_legacy,
    ////            TlsSignatureScheme.rsa_pkcs1_sha384,
    ////            TlsSignatureScheme.ecdsa_secp384r1_sha384,
    ////            TlsSignatureScheme.rsa_pkcs1_sha384_legacy,
    ////            TlsSignatureScheme.rsa_pkcs1_sha512,
    ////            TlsSignatureScheme.ecdsa_secp521r1_sha512,
    ////            TlsSignatureScheme.rsa_pkcs1_sha512_legacy,
    ////            TlsSignatureScheme.eccsi_sha256,
    ////            TlsSignatureScheme.iso_ibs1,
    ////            TlsSignatureScheme.iso_ibs2,
    ////            TlsSignatureScheme.iso_chinese_ibs,
    ////            TlsSignatureScheme.sm2sig_sm3,
    ////            TlsSignatureScheme.gostr34102012_256a,
    ////            TlsSignatureScheme.gostr34102012_256b,
    ////            TlsSignatureScheme.gostr34102012_256c,
    ////            TlsSignatureScheme.gostr34102012_256d,
    ////            TlsSignatureScheme.gostr34102012_512a,
    ////            TlsSignatureScheme.gostr34102012_512b,
    ////            TlsSignatureScheme.gostr34102012_512c,
    ////            TlsSignatureScheme.rsa_pss_rsae_sha256,
    ////            TlsSignatureScheme.rsa_pss_rsae_sha384,
    ////            TlsSignatureScheme.rsa_pss_rsae_sha512,
    ////            TlsSignatureScheme.ed25519,
    ////            TlsSignatureScheme.ed448,
    ////            TlsSignatureScheme.rsa_pss_pss_sha256,
    ////            TlsSignatureScheme.rsa_pss_pss_sha384,
    ////            TlsSignatureScheme.rsa_pss_pss_sha512,
    ////            TlsSignatureScheme.ecdsa_brainpoolP256r1tls13_sha256,
    ////            TlsSignatureScheme.ecdsa_brainpoolP384r1tls13_sha384,
    ////            TlsSignatureScheme.ecdsa_brainpoolP512r1tls13_sha512
    ////        };

    ////    TlsSupportedGroup[] tlsSupportedGroups =
    ////        {
    ////            TlsSupportedGroup.sect163k1,
    ////            TlsSupportedGroup.sect163r1,
    ////            TlsSupportedGroup.sect163r2,
    ////            TlsSupportedGroup.sect193r1,
    ////            TlsSupportedGroup.sect193r2,
    ////            TlsSupportedGroup.sect233k1,
    ////            TlsSupportedGroup.sect233r1,
    ////            TlsSupportedGroup.sect239k1,
    ////            TlsSupportedGroup.sect283k1,
    ////            TlsSupportedGroup.sect283r1,
    ////            TlsSupportedGroup.sect409k1,
    ////            TlsSupportedGroup.sect409r1,
    ////            TlsSupportedGroup.sect571k1,
    ////            TlsSupportedGroup.sect571r1,
    ////            TlsSupportedGroup.secp160k1,
    ////            TlsSupportedGroup.secp160r1,
    ////            TlsSupportedGroup.secp160r2,
    ////            TlsSupportedGroup.secp192k1,
    ////            TlsSupportedGroup.secp192r1,
    ////            TlsSupportedGroup.secp224k1,
    ////            TlsSupportedGroup.secp224r1,
    ////            TlsSupportedGroup.secp256k1,
    ////            TlsSupportedGroup.secp256r1,
    ////            TlsSupportedGroup.secp384r1,
    ////            TlsSupportedGroup.secp521r1,
    ////            TlsSupportedGroup.brainpoolP256r1,
    ////            TlsSupportedGroup.brainpoolP384r1,
    ////            TlsSupportedGroup.brainpoolP512r1,
    ////            TlsSupportedGroup.x25519,
    ////            TlsSupportedGroup.x448,
    ////            TlsSupportedGroup.brainpoolP256r1tls13,
    ////            TlsSupportedGroup.brainpoolP384r1tls13,
    ////            TlsSupportedGroup.brainpoolP512r1tls13,
    ////            TlsSupportedGroup.GC256A,
    ////            TlsSupportedGroup.GC256B,
    ////            TlsSupportedGroup.GC256C,
    ////            TlsSupportedGroup.GC256D,
    ////            TlsSupportedGroup.GC512A,
    ////            TlsSupportedGroup.GC512B,
    ////            TlsSupportedGroup.GC512C,
    ////            TlsSupportedGroup.curveSM2,
    ////            TlsSupportedGroup.ffdhe2048,
    ////            TlsSupportedGroup.ffdhe3072,
    ////            TlsSupportedGroup.ffdhe4096,
    ////            TlsSupportedGroup.ffdhe6144,
    ////            TlsSupportedGroup.ffdhe8192,
    ////            TlsSupportedGroup.arbitrary_explicit_prime_curves,
    ////            TlsSupportedGroup.arbitrary_explicit_char2_curves
    ////        };

    ////    TlsVersion[] tlsVersions =
    ////        {
    ////            TlsVersion.SSL3_PROTOCOL_VERSION,
    ////            TlsVersion.TLS1_0_PROTOCOL_VERSION,
    ////            TlsVersion.TLS1_1_PROTOCOL_VERSION,
    ////            TlsVersion.TLS1_2_PROTOCOL_VERSION,
    ////            TlsVersion.TLS1_3_PROTOCOL_VERSION
    ////        };

    ////    TlsPreSharedKeysKeyExchangeMode[] tlsPreSharedKeysKeyExchangeModes =
    ////        {
    ////            TlsPreSharedKeysKeyExchangeMode.psk_ke,
    ////            TlsPreSharedKeysKeyExchangeMode.psk_dhe_ke
    ////        };

    ////    // https://stackoverflow.com/questions/68622359/c-calculate-key-share-using-private-key-and-public-key-on-ecdhe-x25519
    ////    //byte[] clientPrivateKey;
    ////    //byte[] clientSubjectPublicKeyInfo;
    ////    //ECParameters ecParameters;
    ////    //byte[] sharedSecret;
    ////    //ECCurve ecCurve = new()
    ////    //{
    ////    //    CurveType = ECCurve.ECCurveType.PrimeMontgomery,
    ////    //    B = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    ////    //    A = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07, 0x6d, 0x06 }, // 486662
    ////    //    G = new()
    ////    //    {
    ////    //        X = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9 },
    ////    //        Y = new byte[] { 0x20, 0xae, 0x19, 0xa1, 0xb8, 0xa0, 0x86, 0xb4, 0xe0, 0x1e, 0xdd, 0x2c, 0x77, 0x48, 0xd1, 0x4c, 0x92, 0x3d, 0x4d, 0x7e, 0x6d, 0x7c, 0x61, 0xb2, 0x29, 0xe9, 0xc5, 0xa2, 0x7e, 0xce, 0xd3, 0xd9 }
    ////    //    },
    ////    //    Prime = new byte[] { 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed },
    ////    //    Order = new byte[] { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed },
    ////    //    Cofactor = new byte[] { 8 }
    ////    //};

    ////    //// Generate our initial keys
    ////    //using (var cng = new ECDiffieHellmanCng())
    ////    //{
    ////    //    cng.GenerateKey(ecCurve);

    ////    //    cng.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
    ////    //    cng.HashAlgorithm = CngAlgorithm.Sha256;

    ////    //    clientSubjectPublicKeyInfo = cng.PublicKey.ExportSubjectPublicKeyInfo();
    ////    //    clientPrivateKey = cng.ExportECPrivateKey();
    ////    //    ecParameters = cng.ExportParameters(true);
    ////    //}

    ////    //// https://stackoverflow.com/questions/2623761/marshal-ptrtostructure-and-back-again-and-generic-solution-for-endianness-swap
    ////    //CERT_INFO certInfo;

    ////    //unsafe
    ////    //{
    ////    //    fixed (byte* ptr = &clientSubjectPublicKeyInfo[0])
    ////    //    {
    ////    //        certInfo = Marshal.PtrToStructure<CERT_INFO>((nint)ptr);
    ////    //    }
    ////    //}

    ////    //byte[] clientPublicKey = new byte[certInfo.SubjectPublicKeyInfo.PublicKey.cbData];

    ////    //unsafe
    ////    //{
    ////    //    Marshal.Copy((nint)certInfo.SubjectPublicKeyInfo.PublicKey.pbData, clientPublicKey, 0, (int)certInfo.SubjectPublicKeyInfo.PublicKey.cbData);
    ////    //}

    ////    //byte[] clientPublicKey = clientSubjectPublicKeyInfo.Take(32).ToArray();
    ////    byte[] clientPublicKey = new byte[32];

    ////    new Random().NextBytes(clientPublicKey);

    ////    var keyShares = new KeyShare[] { new(TlsSupportedGroup.x25519, clientPublicKey) };
    ////    var tlsRecord = new ClientHelloTlsRecord(hostName, TlsVersion.TLS1_3_PROTOCOL_VERSION, sslProviderCipherSuiteIds, tlsCompressionMethodIdentifiers, tlsEllipticCurvesPointFormats, tlsSignatureSchemes, tlsSupportedGroups, tlsVersions, tlsPreSharedKeysKeyExchangeModes, keyShares);
    ////    await SendClientHelloAsync(cancellationToken, tlsRecord, socket);

    ////    //// Create shared secret
    ////    //using (var cng = new ECDiffieHellmanCng())
    ////    //{
    ////    //    cng.ImportParameters(ecParameters);

    ////    //    cng.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
    ////    //    cng.HashAlgorithm = CngAlgorithm.Sha256;

    ////    //    var otherKey = CngKey.Import(serverHelloTlsRecord.HandshakeExtensions.Cast<KeyShareExtension>().Single().PublicKey, CngKeyBlobFormat.EccFullPublicBlob);

    ////    //    sharedSecret = cng.DeriveKeyMaterial(otherKey);
    ////    //}
    ////}

    private static async Task<Memory<byte>> SendClientHelloAsync(CancellationToken cancellationToken, Memory<byte> clientHelloBytes, IPEndPoint ipEndPoint)
    {
        //var clientHelloTlsRecord = new ClientHelloTlsRecord(sendBuffer);

        using IMemoryOwner<byte> memoryOwner = MemoryPool<byte>.Shared.Rent(8192);
        Memory<byte> buffer = memoryOwner.Memory[..8192];

        // https://tls12.xargs.org/
        // https://wiki.osdev.org/TLS_Handshake
        using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        CancellationToken timeoutCancellationToken = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, new CancellationTokenSource(2000).Token).Token;

        await socket.ConnectAsync(ipEndPoint, timeoutCancellationToken);

        _ = await socket.SendAsync(clientHelloBytes, timeoutCancellationToken);
        int receivedBytes = await socket.ReceiveAsync(buffer, timeoutCancellationToken);
        Memory<byte> receiveBuffer = buffer[..receivedBytes];

        return receiveBuffer;
    }
}