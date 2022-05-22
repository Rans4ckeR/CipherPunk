namespace RS.Schannel.Manager.API;

using Windows.Win32;

public readonly record struct WindowsCipherSuiteConfiguration(
    SslProviderCipherSuiteId CipherSuite,
    bool AllowedBySCH_USE_STRONG_CRYPTO,
    bool EnabledByDefault,
    SslProviderProtocolId[] Protocols,
    bool ExplicitApplicationRequestOnly = false,
    SslProviderKeyTypeId? PreWindows10EllipticCurve = null);