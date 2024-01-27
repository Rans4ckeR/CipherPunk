namespace CipherPunk.UI;

using CipherPunk.CipherSuiteInfoApi;

internal sealed class EllipticCurvesGroupPolicySettingsViewModel(ILogger logger, IUacService uacService, IEllipticCurveService ellipticCurveService, IGroupPolicyService groupPolicyService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseEllipticCurvesSettingsViewModel(logger, ellipticCurveService, uacService, cipherSuiteInfoApiService)
{
    public string? AdminMessage => Elevated ? null : "Run as Administrator to view and modify the Group Policy settings.";

    protected override IEnumerable<WindowsApiEllipticCurveConfiguration> GetActiveSettingConfiguration()
    {
        if (!Elevated)
            return [];

        List<string> activeGroupPolicyEllipticCurveConfigurationsStrings = [.. groupPolicyService.GetEccCurveOrderPolicy()];

        return EllipticCurveService.GetOperatingSystemAvailableEllipticCurveList()
            .Where(q => activeGroupPolicyEllipticCurveConfigurationsStrings.Contains(q.pwszName, StringComparer.OrdinalIgnoreCase))
            .OrderBy(q => activeGroupPolicyEllipticCurveConfigurationsStrings.IndexOf(q.pwszName));
    }

    protected override void DoExecuteSaveSettingsCommand() => groupPolicyService.UpdateEccCurveOrderPolicy(ModifiedSettingConfigurations!.Select(q => q.Name));

    protected override void DoExecuteResetSettingsCommand() => groupPolicyService.UpdateEccCurveOrderPolicy([]);
}