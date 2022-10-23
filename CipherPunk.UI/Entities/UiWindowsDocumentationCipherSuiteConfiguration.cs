namespace CipherPunk.UI;

using Windows.Win32;
using CipherPunk.CipherSuiteInfoApi;

internal readonly record struct UiWindowsDocumentationCipherSuiteConfiguration(
    ushort Priority,
    SslProviderCipherSuiteId CipherSuite,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault,
    bool Ssl2,
    bool Ssl3,
    bool Tls1,
    bool Tls11,
    bool Tls12,
    bool Tls13,
    bool ExplicitApplicationRequestOnly = false,
    SslProviderKeyTypeId? PreWindows10EllipticCurve = null,
    Security? Security = null);