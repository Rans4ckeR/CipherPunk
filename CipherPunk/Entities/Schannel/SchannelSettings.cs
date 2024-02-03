namespace CipherPunk;

public readonly record struct SchannelSettings(
    SchannelLogLevel? LogLevel,
    SchannelCertificateMappingMethod? CertificateMappingMethods,
    int? ClientCacheTime,
    bool? EnableOcspStaplingForSni,
    int? IssuerCacheSize,
    int? IssuerCacheTime,
    int? MaximumCacheSize,
    bool? SendTrustedIssuerList,
    int? ServerCacheTime,
    int? MessageLimitClient,
    int? MessageLimitServer,
    int? MessageLimitServerClientAuth);