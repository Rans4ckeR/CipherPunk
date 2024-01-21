namespace CipherPunk;

using System.Collections.Frozen;
using System.Runtime.Versioning;

public interface ISchannelService
{
    [SupportedOSPlatform("windows")]
    FrozenSet<SchannelProtocolSettings> GetProtocolSettings();

    [SupportedOSPlatform("windows")]
    void UpdateProtocolSettings(ICollection<SchannelProtocolSettings> schannelProtocolSettings);

    [SupportedOSPlatform("windows")]
    FrozenSet<SchannelKeyExchangeAlgorithmSettings> GetKeyExchangeAlgorithmSettings();

    [SupportedOSPlatform("windows")]
    void UpdateKeyExchangeAlgorithmSettings(ICollection<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings);

    [SupportedOSPlatform("windows")]
    FrozenSet<SchannelHashSettings> GetSchannelHashSettings();

    [SupportedOSPlatform("windows")]
    void UpdateSchannelHashSettings(ICollection<SchannelHashSettings> schannelHashSettings);

    [SupportedOSPlatform("windows")]
    FrozenSet<SchannelCipherSettings> GetSchannelCipherSettings();

    [SupportedOSPlatform("windows")]
    void UpdateSchannelCipherSettings(ICollection<SchannelCipherSettings> schannelCipherSettings);

    [SupportedOSPlatform("windows")]
    SchannelSettings GetSchannelSettings();

    [SupportedOSPlatform("windows")]
    void UpdateSchannelLogSettings(SchannelLogLevel schannelLogLevel);
}