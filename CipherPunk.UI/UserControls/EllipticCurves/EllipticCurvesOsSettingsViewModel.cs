namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.Windows.Media.Imaging;

internal sealed class EllipticCurvesOsSettingsViewModel : BaseViewModel
{
    private readonly IUacIconService uacIconService;
    private readonly IEllipticCurveService ellipticCurveService;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? availableEllipticCurveConfigurations;
    private ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? osDefaultEllipticCurveConfigurations;
    private BitmapSource? uacIcon;

    public EllipticCurvesOsSettingsViewModel(ILogger logger, IUacIconService uacIconService, IEllipticCurveService ellipticCurveService)
        : base(logger)
    {
        this.uacIconService = uacIconService;
        this.ellipticCurveService = ellipticCurveService;

        UpdateCanExecuteDefaultCommand();
    }

    public BitmapSource UacIcon => uacIcon ??= uacIconService.GetUacShieldIcon();

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? ActiveEllipticCurveConfigurations
    {
        get => activeEllipticCurveConfigurations;
        private set => _ = SetProperty(ref activeEllipticCurveConfigurations, value);
    }

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? AvailableEllipticCurveConfigurations
    {
        get => availableEllipticCurveConfigurations;
        private set => _ = SetProperty(ref availableEllipticCurveConfigurations, value);
    }

    public ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? OsDefaultEllipticCurveConfigurations
    {
        get => osDefaultEllipticCurveConfigurations;
        private set => _ = SetProperty(ref osDefaultEllipticCurveConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        await Task.CompletedTask;

        List<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
        List<WindowsApiEllipticCurveConfiguration> windowsApiAvailableEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemAvailableEllipticCurveList();
        List<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfiguration = ellipticCurveService.GetOperatingSystemDefaultEllipticCurveList();

        ushort priority = 0;
        var uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            ++priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(",", q.CngAlgorithms))).ToList();

        var uiWindowsApiAvailableEllipticCurveConfigurations = windowsApiAvailableEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            0,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(",", q.CngAlgorithms))).ToList();

        priority = 0;

        var uiWindowsDocumentationEllipticCurveConfiguration = windowsDocumentationEllipticCurveConfiguration.Select(q => new UiWindowsDocumentationEllipticCurveConfiguration(
            ++priority,
            q.Name,
            q.Identifier,
            q.Code,
            q.TlsSupportedGroup,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault)).ToList();

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);
        AvailableEllipticCurveConfigurations = new(uiWindowsApiAvailableEllipticCurveConfigurations);
        OsDefaultEllipticCurveConfigurations = new(uiWindowsDocumentationEllipticCurveConfiguration);
    }
}