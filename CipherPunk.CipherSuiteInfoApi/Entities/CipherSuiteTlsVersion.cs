namespace CipherPunk.CipherSuiteInfoApi;

public enum CipherSuiteTlsVersion
{
#pragma warning disable CA1707 // Identifiers should not contain underscores
    TLS1_0,

    TLS1_1,

    TLS1_2,

    TLS1_3
#pragma warning restore CA1707 // Identifiers should not contain underscores
}