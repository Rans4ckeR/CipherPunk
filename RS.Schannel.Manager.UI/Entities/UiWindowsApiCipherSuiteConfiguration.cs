namespace RS.Schannel.Manager.UI;

using Windows.Win32;
using RS.Schannel.Manager.CipherSuiteInfoApi;

internal readonly record struct UiWindowsApiCipherSuiteConfiguration(
    ushort Priority,
    bool Ssl2,
    bool Ssl3,
    bool Tls1,
    bool Tls11,
    bool Tls12,
    bool Tls13,
    SslProviderKeyTypeId? KeyType,
    string? Certificate,
    uint? MaximumExchangeLength,
    uint? MinimumExchangeLength,
    string? Exchange,
    uint? HashLength,
    string? Hash,
    uint CipherBlockLength,
    uint CipherLength,
    SslProviderCipherSuiteId BaseCipherSuite,
    SslProviderCipherSuiteId CipherSuite,
    string Cipher,
    string Provider,
    string Image,
    string CipherSuiteName,
    Security? Security = null);