using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class CipherSuitesGroupPolicySettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IGroupPolicyService groupPolicyService)
    : BaseCipherSuitesSettingsViewModel(logger, cipherSuiteService, uacService, cipherSuiteInfoApiService)
{
    private readonly IGroupPolicyService groupPolicyService = groupPolicyService;

    public string? AdminMessage => Elevated ? null : "Run as Administrator to view and modify the Group Policy settings.";

    protected override IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveSettingConfiguration()
    {
        if (!Elevated)
            return [];

        List<string> windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = [.. groupPolicyService.GetSslCipherSuiteOrderPolicy()];

        return CipherSuiteService.GetOperatingSystemActiveCipherSuiteList()
            .Where(q => windowsActiveGroupPolicyCipherSuiteConfigurationsStrings.Contains(q.CipherSuite.ToString(), StringComparer.OrdinalIgnoreCase))
            .OrderBy(q => windowsActiveGroupPolicyCipherSuiteConfigurationsStrings.IndexOf(q.CipherSuite.ToString()));
    }

    protected override void DoExecuteSaveSettingsCommand() => groupPolicyService.UpdateSslCipherSuiteOrderPolicy(ModifiedSettingConfigurations!.Select(static q => q.Id.ToString()));

    protected override void DoExecuteResetSettingsCommand() => groupPolicyService.UpdateSslCipherSuiteOrderPolicy([]);
}