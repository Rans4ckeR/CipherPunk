using Windows.Win32;

namespace CipherPunk;

public readonly record struct WindowsDocumentationCipherSuiteConfiguration(
    ushort Priority,
    SslProviderCipherSuiteId CipherSuite,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault,
    ICollection<SslProviderProtocolId> Protocols,
    bool ExplicitApplicationRequestOnly = false,
    SslProviderKeyTypeId? PreWindows10EllipticCurve = null)
{
    public string GetName() => FormattableString.Invariant($"{CipherSuite}{PreWindows10EllipticCurveName(PreWindows10EllipticCurve)}");

    private static string? PreWindows10EllipticCurveName(SslProviderKeyTypeId? preWindows10EllipticCurve) =>
        preWindows10EllipticCurve switch
        {
            SslProviderKeyTypeId.TLS_ECC_P256_CURVE_KEY_TYPE => "_P256",
            SslProviderKeyTypeId.TLS_ECC_P384_CURVE_KEY_TYPE => "_P384",
            SslProviderKeyTypeId.TLS_ECC_P521_CURVE_KEY_TYPE => "_P512",
            null => null,
            _ => throw new ArgumentOutOfRangeException(nameof(preWindows10EllipticCurve), preWindows10EllipticCurve, null)
        };
}