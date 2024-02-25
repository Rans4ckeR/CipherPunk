namespace CipherPunk;

using Windows.Win32;

internal sealed class Windows81DocumentationService(IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService) : BaseWindowsDocumentationService(WindowsVersion.Windows81OrServer2012R2, windowsEllipticCurveDocumentationService)
{
    protected override IEnumerable<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuiteDefaultEnabledConfiguration()
        =>
        [
            new(1, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(2, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(3, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(4, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(5, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(6, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(7, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(8, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(9, SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(10, SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(11, SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(12, SslProviderCipherSuiteId.TLS_DHE_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(13, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(14, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(15, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(16, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(17, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(18, SslProviderCipherSuiteId.TLS_RSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(19, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(20, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(21, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(22, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(23, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(24, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(25, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(26, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(27, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE),
            new(28, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE),
            new(29, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(30, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION]),
            new(31, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_256_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(32, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_AES_128_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(33, SslProviderCipherSuiteId.TLS_RSA_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION]),
            new(34, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(35, SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_SHA, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(36, SslProviderCipherSuiteId.TLS_RSA_WITH_RC4_128_MD5, false, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(37, SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA256, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], true),
            new(38, SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_SHA, true, true, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION], true),
            new(39, SslProviderCipherSuiteId.SSL_CK_RC4_128_WITH_MD5, false, true, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION], true),
            new(40, SslProviderCipherSuiteId.SSL_CK_DES_192_EDE3_CBC_WITH_MD5, true, true, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION], true)
        ];

    protected override IEnumerable<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuiteDefaultDisabledConfiguration()
        =>
        [
            new(41, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(42, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(43, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(44, SslProviderCipherSuiteId.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(45, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(46, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(47, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(48, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(49, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(50, SslProviderCipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION], false, SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE),
            new(51, SslProviderCipherSuiteId.TLS_RSA_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(52, SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_RC4_56_SHA, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(53, SslProviderCipherSuiteId.TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(54, SslProviderCipherSuiteId.TLS_RSA_EXPORT_WITH_RC4_40_MD5, false, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(55, SslProviderCipherSuiteId.TLS_RSA_WITH_NULL_MD5, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(56, SslProviderCipherSuiteId.TLS_DHE_DSS_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(57, SslProviderCipherSuiteId.TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA, true, false, [SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION, SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION, SslProviderProtocolId.SSL3_PROTOCOL_VERSION]),
            new(58, SslProviderCipherSuiteId.SSL_CK_DES_64_CBC_WITH_MD5, true, false, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION]),
            new(59, SslProviderCipherSuiteId.SSL_CK_RC4_128_EXPORT40_WITH_MD5, false, false, [SslProviderProtocolId.SSL2_PROTOCOL_VERSION])
        ];
}