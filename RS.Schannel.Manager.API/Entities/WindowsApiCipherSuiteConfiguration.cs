namespace RS.Schannel.Manager.API;

using Windows.Win32;

public readonly record struct WindowsApiCipherSuiteConfiguration(
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
    string Image,
    string CipherSuiteName);
    //string? CipherMode);