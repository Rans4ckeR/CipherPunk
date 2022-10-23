namespace CipherPunk;

using Windows.Win32;
using CipherPunk.CipherSuiteInfoApi;

public readonly record struct CipherSuiteConfiguration(
    SslProviderCipherSuiteId CipherSuite,
    bool AllowedBySCH_USE_STRONG_CRYPTO,
    bool EnabledByDefault,
    SslProviderProtocolId[] WindowsApiProtocols,
    SslProviderProtocolId[] WindowsDocumentationProtocols,
    SslProviderKeyTypeId KeyType,
    string Certificate,
    uint MaximumExchangeLength,
    uint MinimumExchangeLength,
    string Exchange,
    uint HashLength,
    string Hash,
    uint CipherBlockLength,
    uint CipherLength,
    SslProviderCipherSuiteId BaseCipherSuite,
    string Cipher,
    string Provider,
    string Function,
    string Image,
    CipherSuite OnlineInfo,
    bool ExplicitApplicationRequestOnly = false,
    SslProviderKeyTypeId? PreWindows10EllipticCurve = null);