using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class EllipticCurvesOsSettingsViewModel(ILogger logger, IUacService uacService, IEllipticCurveService ellipticCurveService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseEllipticCurvesSettingsViewModel(logger, ellipticCurveService, uacService, cipherSuiteInfoApiService)
{
    public string? AdminMessage => Elevated ? null : "Run as Administrator to modify the OS settings.";

    protected override IEnumerable<WindowsApiEllipticCurveConfiguration> GetActiveSettingConfiguration()
        => EllipticCurveService.GetOperatingSystemConfiguredEllipticCurveList();

    protected override void DoExecuteSaveSettingsCommand()
        => EllipticCurveService.UpdateEllipticCurveOrder(ModifiedSettingConfigurations!.Select(q => q.Name));

    protected override void DoExecuteResetSettingsCommand()
        => EllipticCurveService.ResetEllipticCurveListToOperatingSystemDefault();
}