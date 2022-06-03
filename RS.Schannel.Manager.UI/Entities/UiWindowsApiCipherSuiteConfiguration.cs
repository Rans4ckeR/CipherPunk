namespace RS.Schannel.Manager.UI;

using Windows.Win32;
using RS.Schannel.Manager.CipherSuiteInfoApi;

internal readonly record struct UiWindowsApiCipherSuiteConfiguration(
    ushort Priority,
    List<SslProviderProtocolId> Protocols,
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
    string Function,
    string Image,
    Security? Security = null);