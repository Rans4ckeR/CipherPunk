namespace CipherPunk;

using System.Collections.Frozen;
using System.Runtime.Versioning;

public interface ISchannelService
{
    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<SchannelProtocolSettings> GetProtocolSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateProtocolSettings(IEnumerable<SchannelProtocolSettings> schannelProtocolSettings);

    [SupportedOSPlatform("windows")]
    void ResetProtocolSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<SchannelKeyExchangeAlgorithmSettings> GetKeyExchangeAlgorithmSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateKeyExchangeAlgorithmSettings(IEnumerable<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings);

    [SupportedOSPlatform("windows")]
    void ResetKeyExchangeAlgorithmSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<SchannelHashSettings> GetSchannelHashSettings();
#pragma warning restore CA1024 // Use properties where appropriate

    [SupportedOSPlatform("windows")]
    void UpdateSchannelHashSettings(IEnumerable<SchannelHashSettings> schannelHashSettings);

    [SupportedOSPlatform("windows")]
    void ResetSchannelHashSettings();

    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<SchannelCipherSettings> GetSchannelCipherSettings();
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