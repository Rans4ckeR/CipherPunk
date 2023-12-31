namespace CipherPunk.UI;

internal sealed class EllipticCurvesOsSettingsViewModel(ILogger logger, IUacIconService uacIconService, IEllipticCurveService ellipticCurveService)
    : BaseEllipticCurvesSettingsViewModel(logger, ellipticCurveService, uacIconService)
{
    protected override IEnumerable<WindowsApiEllipticCurveConfiguration> GetActiveSettingConfiguration()
        => EllipticCurveService.GetOperatingSystemActiveEllipticCurveList();

    protected override void DoExecuteSaveSettingsCommand()
        => EllipticCurveService.UpdateEllipticCurveOrder(ModifiedSettingConfigurations!.Select(q => q.Name).ToArray());

    protected override void DoExecuteResetSettingsCommand()
        => EllipticCurveService.ResetEllipticCurveListToOperatingSystemDefault();
}