namespace RS.Schannel.Manager.API;

using Windows.Win32;

public sealed class WindowsApiCipherSuiteConfiguration
{
    public List<SslProviderProtocolId> Protocols { get; set; }

    public SslProviderKeyTypeId KeyType { get; set; }

    public string Certificate { get; set; }

    public uint MaximumExchangeLength { get; set; }

    public uint MinimumExchangeLength { get; set; }

    public string Exchange { get; set; }

    public uint HashLength { get; set; }

    public string Hash { get; set; }

    public uint CipherBlockLength { get; set; }

    public uint CipherLength { get; set; }

    public SslProviderCipherSuiteId BaseCipherSuite { get; set; }

    public SslProviderCipherSuiteId CipherSuite { get; set; }

    public string Cipher { get; set; }

    public string Provider { get; set; }

    public string Function { get; set; }

    public string Image { get; set; }
}