namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.Windows.Media.Imaging;

internal sealed class EllipticCurvesViewModel : BaseViewModel
{
    private readonly IUacIconService uacIconService;
    private readonly IEllipticCurveService ellipticCurveService;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;
    private BitmapSource? uacIcon;

    public EllipticCurvesViewModel(ILogger logger, IUacIconService uacIconService, IEllipticCurveService ellipticCurveService)
        : base(logger)
    {
        this.uacIconService = uacIconService;
        this.ellipticCurveService = ellipticCurveService;

        UpdateCanExecuteDefaultCommand();
    }

    public BitmapSource UacIcon
    {
        get => uacIcon ??= uacIconService.GetUacShieldIcon();
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
            q.dwGroupId,
            q.dwMagic,
            q.algId,
            q.dwBitLength,
            q.bcryptMagic,
            q.flags,
            string.Join(",", q.CngAlgorithms),
            q.pwszCNGExtraAlgid)).ToList();

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);
    }
}