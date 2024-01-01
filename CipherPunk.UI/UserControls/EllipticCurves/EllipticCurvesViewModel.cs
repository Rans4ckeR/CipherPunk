namespace CipherPunk.UI;

using System.Collections.ObjectModel;

internal sealed class EllipticCurvesViewModel : BaseViewModel
{
    private readonly IEllipticCurveService ellipticCurveService;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;

    public EllipticCurvesViewModel(ILogger logger, IEllipticCurveService ellipticCurveService, IUacService uacService)
        : base(logger, uacService)
    {
        this.ellipticCurveService = ellipticCurveService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? ActiveEllipticCurveConfigurations
    {
        get => activeEllipticCurveConfigurations;
        private set => _ = SetProperty(ref activeEllipticCurveConfigurations, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        List<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();

        ushort priority = ushort.MinValue;
        var uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            ++priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms))).ToList();

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);

        return Task.CompletedTask;
    }
}