namespace CipherPunk.UI;

internal sealed class EllipticCurvesOsSettingsViewModel(ILogger logger, IUacService uacService, IEllipticCurveService ellipticCurveService)
    : BaseEllipticCurvesSettingsViewModel(logger, ellipticCurveService, uacService)
{
    public string? AdminMessage => Elevated ? null : "Run as Administrator to modify the OS settings.";

    protected override IEnumerable<WindowsApiEllipticCurveConfiguration> GetActiveSettingConfiguration()
        => EllipticCurveService.GetOperatingSystemConfiguredEllipticCurveList();

    protected override void DoExecuteSaveSettingsCommand()
        => EllipticCurveService.UpdateEllipticCurveOrder(ModifiedSettingConfigurations!.Select(q => q.Name));

    protected override void DoExecuteResetSettingsCommand()
        => EllipticCurveService.ResetEllipticCurveListToOperatingSystemDefault();
}