namespace CipherPunk.UI;

internal sealed class EllipticCurvesGroupPolicySettingsViewModel(ILogger logger, IUacIconService uacIconService, IEllipticCurveService ellipticCurveService, IGroupPolicyService groupPolicyService)
    : BaseEllipticCurvesSettingsViewModel(logger, ellipticCurveService, uacIconService)
{
    protected override IEnumerable<WindowsApiEllipticCurveConfiguration> GetActiveSettingConfiguration()
    {
        string[] activeGroupPolicyEllipticCurveConfigurationsStrings = [];

        AdminMessage = null;

        try
        {
            activeGroupPolicyEllipticCurveConfigurationsStrings = groupPolicyService.GetEccCurveOrderPolicy();
        }
        catch (UnauthorizedAccessException)
        {
            AdminMessage = "Run as Administrator to view and modify the Group Policy settings.";
        }

        return EllipticCurveService.GetOperatingSystemActiveEllipticCurveList().Where(q => activeGroupPolicyEllipticCurveConfigurationsStrings.Contains(q.pwszName, StringComparer.OrdinalIgnoreCase));
    }

    protected override void DoExecuteSaveSettingsCommand() => groupPolicyService.UpdateEccCurveOrderPolicy(ModifiedSettingConfigurations!.Select(q => q.Name).ToArray());

    protected override void DoExecuteResetSettingsCommand() => groupPolicyService.UpdateEccCurveOrderPolicy([]);
}