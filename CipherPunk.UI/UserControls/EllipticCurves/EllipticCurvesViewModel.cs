namespace CipherPunk.UI;

using System.Collections.Frozen;
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
        FrozenSet<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
        IOrderedEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            q.Priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)))
            .OrderBy(q => q.Priority);

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);

        return Task.CompletedTask;
    }
}