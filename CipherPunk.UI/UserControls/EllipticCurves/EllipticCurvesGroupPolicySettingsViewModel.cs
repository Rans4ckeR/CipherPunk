namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.Windows.Media.Imaging;

internal sealed class EllipticCurvesGroupPolicySettingsViewModel : BaseViewModel
{
    private readonly IUacIconService uacIconService;
    private readonly IEllipticCurveService ellipticCurveService;
    private readonly IGroupPolicyService groupPolicyService;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? availableEllipticCurveConfigurations;
    private ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? groupPolicyDefaultEllipticCurveConfigurations;
    private BitmapSource? uacIcon;
    private string? adminMessage;

    public EllipticCurvesGroupPolicySettingsViewModel(ILogger logger, IUacIconService uacIconService, IEllipticCurveService ellipticCurveService, IGroupPolicyService groupPolicyService)
        : base(logger)
    {
        this.uacIconService = uacIconService;
        this.ellipticCurveService = ellipticCurveService;
        this.groupPolicyService = groupPolicyService;

        UpdateCanExecuteDefaultCommand();
    }

    public string? AdminMessage
    {
        get => adminMessage;
        private set => _ = SetProperty(ref adminMessage, value);
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

    public ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? GroupPolicyDefaultEllipticCurveConfigurations
    {
        get => groupPolicyDefaultEllipticCurveConfigurations;
        private set => _ = SetProperty(ref groupPolicyDefaultEllipticCurveConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        await Task.CompletedTask;

        string[] activeGroupPolicyEllipticCurveConfigurationsStrings = [];

        AdminMessage = null;

        try
        {
            activeGroupPolicyEllipticCurveConfigurationsStrings = groupPolicyService.GetEccCurveOrderPolicy();
        }
        catch (UnauthorizedAccessException)
        {
            AdminMessage = "Run as Administrator to see the active Group Policy settings.";
        }

        List<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationDefaultEllipticCurveConfiguration = ellipticCurveService.GetOperatingSystemDefaultEllipticCurveList();
        List<WindowsApiEllipticCurveConfiguration> windowsApiAvailableEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemAvailableEllipticCurveList();
        IEnumerable<WindowsApiEllipticCurveConfiguration> activeGroupPolicyEllipticCurveConfigurations = windowsApiAvailableEllipticCurveConfigurations.Where(q => activeGroupPolicyEllipticCurveConfigurationsStrings.Contains(q.pwszName));

        ushort priority = 0;
        var uiWindowsApiEllipticCurveConfigurations = activeGroupPolicyEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
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

        var uiWindowsDocumentationDefaultEllipticCurveConfiguration = windowsDocumentationDefaultEllipticCurveConfiguration.Select(q => new UiWindowsDocumentationEllipticCurveConfiguration(
            ++priority,
            q.Name,
            q.Identifier,
            q.Code,
            q.TlsSupportedGroup,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault)).ToList();

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);
        AvailableEllipticCurveConfigurations = new(uiWindowsApiAvailableEllipticCurveConfigurations);
        GroupPolicyDefaultEllipticCurveConfigurations = new(uiWindowsDocumentationDefaultEllipticCurveConfiguration);
    }
}