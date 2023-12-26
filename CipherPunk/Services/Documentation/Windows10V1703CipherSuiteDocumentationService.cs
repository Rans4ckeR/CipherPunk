namespace CipherPunk;

using Windows.Win32;

internal static class Windows10V1703CipherSuiteDocumentationService
{
    public static (WindowsSchannelVersion Version, List<WindowsDocumentationCipherSuiteConfiguration> Configurations) GetConfiguration()
        => (WindowsSchannelVersion.Windows10V1703, [.. GetDefaultEnabledConfiguration(), .. GetDefaultDisabledConfiguration(), .. GetPreSharedKeyConfiguration()]);

    private static List<WindowsDocumentationCipherSuiteConfiguration> GetDefaultEnabledConfiguration()
        => new()
        {
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_SHA, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_MD5, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA256, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION], true)
        };

    private static List<WindowsDocumentationCipherSuiteConfiguration> GetDefaultDisabledConfiguration()
        => new()
        {
            new(SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_DES_CBC_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_DES_CBC_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_MD5, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_EXPORT_WITH_RC4_40_MD5, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION])
        };

    private static List<WindowsDocumentationCipherSuiteConfiguration> GetPreSharedKeyConfiguration()
        => new()
        {
            new(SslProviderCipherSuiteId.TLS_PSK_WITH_AES_256_GCM_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_PSK_WITH_AES_128_GCM_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_PSK_WITH_AES_256_CBC_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_PSK_WITH_AES_128_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_PSK_WITH_NULL_SHA384, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_PSK_WITH_NULL_SHA256, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true)
        };
}