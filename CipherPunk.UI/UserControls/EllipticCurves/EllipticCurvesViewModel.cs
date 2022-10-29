namespace CipherPunk.UI;

using System.Collections.ObjectModel;

internal sealed class EllipticCurvesViewModel : BaseViewModel
{
    private readonly IEllipticCurveService ellipticCurveService;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;

    public EllipticCurvesViewModel(ILogger logger, IEllipticCurveService ellipticCurveService)
        : base(logger)
    {
        this.ellipticCurveService = ellipticCurveService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? ActiveEllipticCurveConfigurations
    {
        get => activeEllipticCurveConfigurations;
        private set => _ = SetProperty(ref activeEllipticCurveConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        await Task.CompletedTask;

        List<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();

        ushort priority = 0;
        var uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            ++priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(",", q.CngAlgorithms))).ToList();

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);
    }
}