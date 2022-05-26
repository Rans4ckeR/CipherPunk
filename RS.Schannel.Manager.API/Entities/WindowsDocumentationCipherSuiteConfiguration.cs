namespace RS.Schannel.Manager.API;

using Windows.Win32;

public readonly record struct WindowsDocumentationCipherSuiteConfiguration(
    SslProviderCipherSuiteId CipherSuite,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault,
    SslProviderProtocolId[] Protocols,
    bool ExplicitApplicationRequestOnly = false,
    SslProviderKeyTypeId? PreWindows10EllipticCurve = null);