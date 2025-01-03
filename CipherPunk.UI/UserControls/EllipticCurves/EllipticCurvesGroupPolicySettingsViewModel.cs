﻿using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class EllipticCurvesGroupPolicySettingsViewModel(ILogger logger, IUacService uacService, IEllipticCurveService ellipticCurveService, IGroupPolicyService groupPolicyService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseEllipticCurvesSettingsViewModel(logger, ellipticCurveService, uacService, cipherSuiteInfoApiService)
{
    private readonly IGroupPolicyService groupPolicyService = groupPolicyService;

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

    protected override void DoExecuteSaveSettingsCommand() => groupPolicyService.UpdateEccCurveOrderPolicy(ModifiedSettingConfigurations!.Select(static q => q.Name));

    protected override void DoExecuteResetSettingsCommand() => groupPolicyService.UpdateEccCurveOrderPolicy([]);
}