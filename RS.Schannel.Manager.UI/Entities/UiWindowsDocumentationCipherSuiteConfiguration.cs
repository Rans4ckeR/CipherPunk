namespace RS.Schannel.Manager.UI;

using Windows.Win32;
using RS.Schannel.Manager.CipherSuiteInfoApi;

internal readonly record struct UiWindowsDocumentationCipherSuiteConfiguration(
    ushort Priority,
    SslProviderCipherSuiteId CipherSuite,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault,
    SslProviderProtocolId[] Protocols,
    bool ExplicitApplicationRequestOnly = false,
    SslProviderKeyTypeId? PreWindows10EllipticCurve = null,
    Security? Security = null);