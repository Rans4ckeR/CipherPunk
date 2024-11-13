using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

namespace CipherPunk.UI;

internal readonly record struct UiWindowsApiCipherSuiteConfiguration(
    ushort Priority,
    SslProviderCipherSuiteId Id,
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
    string Cipher,
    CipherSuiteSecurity? Security = null);