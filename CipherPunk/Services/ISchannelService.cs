namespace CipherPunk;

using System.Runtime.Versioning;

public interface ISchannelService
{
    [SupportedOSPlatform("windows")]
    List<SchannelProtocolSettings> GetProtocolSettings();

    [SupportedOSPlatform("windows")]
    void UpdateProtocolSettings(List<SchannelProtocolSettings> schannelProtocolSettings);

    [SupportedOSPlatform("windows")]
    List<SchannelKeyExchangeAlgorithmSettings> GetKeyExchangeAlgorithmSettings();

    [SupportedOSPlatform("windows")]
    void UpdateKeyExchangeAlgorithmSettings(List<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings);

    [SupportedOSPlatform("windows")]
    List<SchannelHashSettings> GetSchannelHashSettings();

    [SupportedOSPlatform("windows")]
    void UpdateSchannelHashSettings(List<SchannelHashSettings> schannelHashSettings);

    [SupportedOSPlatform("windows")]
    List<SchannelCipherSettings> GetSchannelCipherSettings();

    [SupportedOSPlatform("windows")]
    void UpdateSchannelCipherSettings(List<SchannelCipherSettings> schannelCipherSettings);

    [SupportedOSPlatform("windows")]
    SchannelSettings GetSchannelSettings();

    [SupportedOSPlatform("windows")]
    void UpdateSchannelLogSettings(SchannelLogLevel schannelLogLevel);
}