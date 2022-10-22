namespace RS.Schannel.Manager.UI;

using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using Microsoft.Extensions.Logging;
using RS.Schannel.Manager.API;

internal sealed class EllipticCurvesViewModel : BaseViewModel
{
    private readonly IUacIconService uacIconService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly IEllipticCurveService ellipticCurveService;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? availableEllipticCurveConfigurations;
    private ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? osDefaultEllipticCurveConfigurations;
    private BitmapSource? uacIcon;

    public EllipticCurvesViewModel(ILogger logger, IUacIconService uacIconService, IGroupPolicyService groupPolicyService, IEllipticCurveService ellipticCurveService)
        : base(logger)
    {
        this.uacIconService = uacIconService;
        this.groupPolicyService = groupPolicyService;
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
        List<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
        List<WindowsApiEllipticCurveConfiguration> windowsApiAvailableEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemAvailableEllipticCurveList();
        List<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfiguration = ellipticCurveService.GetOperatingSystemDefaultEllipticCurveList();
        string ddd = await groupPolicyService.GetSslCurveOrderPolicyWindowsDefaultsAsync(cancellationToken);

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

        var uiWindowsApiAvailableEllipticCurveConfigurations = windowsApiAvailableEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            0,
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