namespace CipherPunk;

using Windows.Win32;

public readonly record struct TlsClientHello(
    SslProviderCipherSuiteId[] SslProviderCipherSuiteIds,
    TlsCompressionMethodIdentifier[] TlsCompressionMethodIdentifiers);