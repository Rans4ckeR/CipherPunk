using Windows.Win32;

namespace CipherPunk;

public readonly record struct WindowsApiCipherSuiteConfiguration(
    ushort Priority,
    ICollection<SslProviderProtocolId> Protocols,
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
    string CipherSuiteName);