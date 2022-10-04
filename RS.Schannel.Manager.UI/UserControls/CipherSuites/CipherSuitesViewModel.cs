namespace RS.Schannel.Manager.UI;

using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using RS.Schannel.Manager.CipherSuiteInfoApi;
using Microsoft.Extensions.Logging;
using RS.Schannel.Manager.API;

internal sealed class CipherSuitesViewModel : BaseViewModel
{
    private readonly ISchannelService schannelService;
    private readonly IUacIconService uacIconService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = new();
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? osDefaultCipherSuiteConfigurations;
    private ObservableCollection<CipherSuiteConfiguration>? cipherSuiteConfigurations;
    private BitmapSource? uacIcon;
    private bool fetchOnlineInfo = true;

    public CipherSuitesViewModel(ILogger logger, ISchannelService schannelService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IGroupPolicyService groupPolicyService)
        : base(logger)
    {
        this.schannelService = schannelService;
        this.uacIconService = uacIconService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
        this.groupPolicyService = groupPolicyService;

        UpdateCanExecuteDefaultCommand();
    }

    public BitmapSource UacIcon
    {
        get => uacIcon ??= uacIconService.GetUacShieldIcon();
    }

    public bool FetchOnlineInfo
    {
        get => fetchOnlineInfo;
        set => _ = SetProperty(ref fetchOnlineInfo, value);
    }

    public ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? ActiveCipherSuiteConfigurations
    {
        get => activeCipherSuiteConfigurations;
        private set => _ = SetProperty(ref activeCipherSuiteConfigurations, value);
    }

    public ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? OsDefaultCipherSuiteConfigurations
    {
        get => osDefaultCipherSuiteConfigurations;
        private set => _ = SetProperty(ref osDefaultCipherSuiteConfigurations, value);
    }

    public ObservableCollection<CipherSuiteConfiguration>? CipherSuiteConfigurations
    {
        get => cipherSuiteConfigurations;
        private set => _ = SetProperty(ref cipherSuiteConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        //schannelService.ResetEllipticCurveListToOperatingSystemDefault();

        var x = schannelService.GetOperatingSystemActiveEllipticCurveList();
        var y = schannelService.GetOperatingSystemAvailableEllipticCurveList();
        var z = schannelService.GetOperatingSystemDefaultEllipticCurveList();
        var ffff = await groupPolicyService.GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(cancellationToken);
        var ddd = await groupPolicyService.GetSslCurveOrderPolicyWindowsDefaultsAsync(cancellationToken);
        var hhhh = schannelService.GetOperatingSystemDefaultCipherSuiteList();

        //groupPolicyService.UpdateSslCipherSuiteOrderPolicy(Array.Empty<string>());

        //groupPolicyService.UpdateSslCipherSuiteOrderPolicy(new[]
        //{
        //    "TLS_AES_256_GCM_SHA384",
        //    "TLS_AES_128_GCM_SHA256",
        //    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        //    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        //    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        //    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        //    "TLS_RSA_WITH_AES_256_CBC_SHA"
        //});

        List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = schannelService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        List<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = schannelService.GetOperatingSystemActiveCipherSuiteList();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        ushort priority = 0;
        var uiWindowsApiCipherSuiteConfigurations = windowsApiActiveCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
            ++priority,
            q.Protocols,
            q.KeyType,
            q.Certificate,
            q.MaximumExchangeLength,
            q.MinimumExchangeLength,
            q.Exchange,
            q.HashLength,
            q.Hash,
            q.CipherBlockLength,
            q.CipherLength,
            q.BaseCipherSuite,
            q.CipherSuite,
            q.Cipher,
            q.Provider,
            q.Image,
            q.CipherSuiteName,
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security)).ToList();

        priority = 0;

        var uiWindowsDocumentationCipherSuiteConfigurations = windowsDocumentationCipherSuiteConfigurations.Select(q => new UiWindowsDocumentationCipherSuiteConfiguration(
            ++priority,
            q.CipherSuite,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault,
            q.Protocols,
            q.ExplicitApplicationRequestOnly,
            q.PreWindows10EllipticCurve,
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security)).ToList();

        ActiveCipherSuiteConfigurations = new(uiWindowsApiCipherSuiteConfigurations);
        OsDefaultCipherSuiteConfigurations = new(uiWindowsDocumentationCipherSuiteConfigurations);
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => cipherSuiteInfoApiService.GetCipherSuite(q.CipherSuite.ToString(), cancellationToken)));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}