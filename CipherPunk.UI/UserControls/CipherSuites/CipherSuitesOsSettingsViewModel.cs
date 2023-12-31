namespace CipherPunk.UI;

using CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuitesOsSettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacIconService, cipherSuiteInfoApiService)
{
    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveSettingConfiguration() => CipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

    protected override void DoExecuteSaveSettingsCommand() => CipherSuiteService.UpdateCipherSuiteOrder(ModifiedSettingConfigurations!.Select(q => q.Id).ToArray());

    protected override void DoExecuteResetSettingsCommand() => CipherSuiteService.ResetCipherSuiteListToOperatingSystemDefault();
}