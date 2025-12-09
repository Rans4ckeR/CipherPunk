using System.Runtime.Versioning;

namespace CipherPunk;

public interface ISchannelService
{
    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<SchannelProtocolSettings> GetProtocolSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateProtocolSettings(IEnumerable<SchannelProtocolSettings> schannelProtocolSettings);

    [SupportedOSPlatform("windows")]
    void ResetProtocolSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<SchannelKeyExchangeAlgorithmSettings> GetKeyExchangeAlgorithmSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateKeyExchangeAlgorithmSettings(IEnumerable<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings);

    [SupportedOSPlatform("windows")]
    void ResetKeyExchangeAlgorithmSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<SchannelHashSettings> GetSchannelHashSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateSchannelHashSettings(IEnumerable<SchannelHashSettings> schannelHashSettings);

    [SupportedOSPlatform("windows")]
    void ResetSchannelHashSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<SchannelCipherSettings> GetSchannelCipherSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateSchannelCipherSettings(IEnumerable<SchannelCipherSettings> schannelCipherSettings);

    [SupportedOSPlatform("windows")]
    void ResetSchannelCipherSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    SchannelSettings GetSchannelSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateSchannelSettings(SchannelSettings schannelSettings);

    [SupportedOSPlatform("windows")]
    void ResetSchannelSettings();
}