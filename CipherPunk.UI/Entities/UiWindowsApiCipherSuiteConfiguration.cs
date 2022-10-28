namespace CipherPunk.UI;

using Windows.Win32;
using CipherPunk.CipherSuiteInfoApi;

internal readonly record struct UiWindowsApiCipherSuiteConfiguration(
    ushort Priority,
    SslProviderCipherSuiteId CipherSuite,
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
    string Provider,
    string Image,
    Security? Security = null);