namespace CipherPunk;

using System.Collections.Frozen;
using Windows.Win32;

internal static class WindowsVistaCipherSuiteDocumentationService
{
    public static KeyValuePair<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> GetConfiguration()
        => new(WindowsVersion.WindowsVistaOrServer2008, FrozenSet.ToFrozenSet([.. GetDefaultEnabledConfiguration(), .. GetDefaultDisabledConfiguration()]));

    private static FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetDefaultEnabledConfiguration()
        => FrozenSet.ToFrozenSet<WindowsDocumentationCipherSuiteConfiguration>(
        [
            new(1, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(2, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(3, SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_SHA, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(4, SslProviderCipherSuiteId.TLS_RSA_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(5, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(6, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(7, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(8, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(9, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(10, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(11, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(12, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(13, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(14, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(15, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(16, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(17, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(18, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(19, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(20, SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_MD5, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(21, SslProviderCipherSuiteId.SSL_CK_RC4_128_WITH_MD5, false, true, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION]),
            new(22, SslProviderCipherSuiteId.SSL_CK_DES_192_EDE3_CBC_WITH_MD5, false, true, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION])
        ]);

    private static FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetDefaultDisabledConfiguration()
        => FrozenSet.ToFrozenSet<WindowsDocumentationCipherSuiteConfiguration>(
        [
            new(23, SslProviderCipherSuiteId.TLS_RSA_EXPORT_WITH_RC4_40_MD5, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(24, SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(25, SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(26, SslProviderCipherSuiteId.SSL_CK_RC4_128_EXPORT40_WITH_MD5, true, false, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION]),
            new(27, SslProviderCipherSuiteId.SSL_CK_DES_64_CBC_WITH_MD5, true, false, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION]),
            new(28, SslProviderCipherSuiteId.TLS_RSA_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(29, SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_MD5, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(30, SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(31, SslProviderCipherSuiteId.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(32, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION])
        ]);
}