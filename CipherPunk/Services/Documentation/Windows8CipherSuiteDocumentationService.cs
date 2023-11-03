﻿namespace CipherPunk;

using Windows.Win32;

internal static class Windows8CipherSuiteDocumentationService
{
#pragma warning disable SA1010 // Opening square brackets should be spaced correctly
    public static (WindowsSchannelVersion Version, List<WindowsDocumentationCipherSuiteConfiguration> Configurations) GetConfiguration()
        => (WindowsSchannelVersion.Windows8OrServer2012, [.. GetDefaultEnabledConfiguration(), .. GetDefaultDisabledConfiguration()]);

    private static List<WindowsDocumentationCipherSuiteConfiguration> GetDefaultEnabledConfiguration()
        => new()
        {
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_SHA, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_MD5, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.SSL_CK_RC4_128_WITH_MD5, false, true, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION], true),
            new(SslProviderCipherSuiteId.SSL_CK_DES_192_EDE3_CBC_WITH_MD5, true, true, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION], true)
        };

    private static List<WindowsDocumentationCipherSuiteConfiguration> GetDefaultDisabledConfiguration()
        => new()
        {
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_EXPORT_WITH_RC4_40_MD5, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_MD5, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.SSL_CK_DES_64_CBC_WITH_MD5, true, false, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION]),
            new(SslProviderCipherSuiteId.SSL_CK_RC4_128_EXPORT40_WITH_MD5, false, false, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION])
        };
#pragma warning restore SA1010 // Opening square brackets should be spaced correctly
}