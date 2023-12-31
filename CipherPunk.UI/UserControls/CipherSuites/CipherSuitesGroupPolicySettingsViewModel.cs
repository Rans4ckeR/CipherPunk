namespace CipherPunk.UI;

using CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuitesGroupPolicySettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IGroupPolicyService groupPolicyService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacIconService, cipherSuiteInfoApiService)
{
    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveSettingConfiguration()
    {
        string[] windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = [];

        AdminMessage = null;

        try
        {
            windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = groupPolicyService.GetSslCipherSuiteOrderPolicy();
        }
        catch (UnauthorizedAccessException)
        {
            AdminMessage = "Run as Administrator to view and modify the Group Policy settings.";
        }

        return CipherSuiteService.GetOperatingSystemActiveCipherSuiteList().Where(q => windowsActiveGroupPolicyCipherSuiteConfigurationsStrings.Contains(q.CipherSuite.ToString(), StringComparer.OrdinalIgnoreCase));
    }

    protected override void DoExecuteSaveSettingsCommand() => groupPolicyService.UpdateSslCipherSuiteOrderPolicy(ModifiedSettingConfigurations!.Select(q => q.Id.ToString()).ToArray());

    protected override void DoExecuteResetSettingsCommand() => groupPolicyService.UpdateSslCipherSuiteOrderPolicy([]);
}