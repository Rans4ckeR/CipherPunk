namespace CipherPunk.UI;

using CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuitesOsSettingsViewModel(
    ILogger logger,
    ICipherSuiteService cipherSuiteService,
    IUacIconService uacIconService,
    ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacIconService, cipherSuiteInfoApiService)
{
    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveCipherSuiteConfiguration()
        => CipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

    protected override void DoExecuteSaveCipherSuitesCommand() => CipherSuiteService.UpdateCipherSuiteOrder(ModifiedCipherSuiteConfigurations!.Select(q => q.Id).ToArray());

    protected override void DoExecuteResetCipherSuitesCommand() => CipherSuiteService.ResetCipherSuiteListToOperatingSystemDefault();
}