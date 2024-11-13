using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class CipherSuitesOsSettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacService, cipherSuiteInfoApiService)
{
    public string? AdminMessage => Elevated ? null : "Run as Administrator to modify the OS settings.";

    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveSettingConfiguration() => CipherSuiteService.GetOperatingSystemConfiguredCipherSuiteList().OrderBy(q => q.Priority);

    protected override void DoExecuteSaveSettingsCommand() => CipherSuiteService.UpdateCipherSuiteOrder(ModifiedSettingConfigurations!.Select(q => q.Id));

    protected override void DoExecuteResetSettingsCommand() => CipherSuiteService.ResetCipherSuiteListToOperatingSystemDefault();
}