namespace CipherPunk;

public readonly record struct SchannelSettings(
    SchannelLogLevel? LogLevel,
    CertificateMappingMethod? CertificateMappingMethods,
    int? ClientCacheTime,
    bool? EnableOcspStaplingForSni,
    bool? FipsAlgorithmPolicy,
    int? IssuerCacheSize,
    int? IssuerCacheTime,
    int? MaximumCacheSize,
    bool? SendTrustedIssuerList,
    int? ServerCacheTime,
    int? MessageLimitClient,
    int? MessageLimitServer,
    int? MessageLimitServerClientAuth);