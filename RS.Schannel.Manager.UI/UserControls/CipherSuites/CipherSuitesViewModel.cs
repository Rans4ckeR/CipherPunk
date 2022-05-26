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
    private readonly List<Ciphersuite?> onlineCipherSuiteInfos = new();
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? osDefaultCipherSuiteConfigurations;
    private ObservableCollection<CipherSuiteConfiguration>? cipherSuiteConfigurations;
    private BitmapSource? uacIcon;
    private bool fetchOnlineInfo = true;

    public CipherSuitesViewModel(ILogger logger, ISchannelService schannelService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger)
    {
        this.schannelService = schannelService;
        this.uacIconService = uacIconService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;

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
        //new GroupPolicyService().X();

        List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = schannelService.GetOperatingSystemDefaultCipherSuiteList();
        List<WindowsApiCipherSuiteConfiguration> windowsApiCipherSuiteConfigurations = await schannelService.GetOperatingSystemActiveCipherSuiteListAsync(cancellationToken);

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfo(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        ushort priority = 0;

        var uiWindowsApiCipherSuiteConfigurations = windowsApiCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
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
            q.Function,
            q.Image,
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

        ActiveCipherSuiteConfigurations = new ObservableCollection<UiWindowsApiCipherSuiteConfiguration>(uiWindowsApiCipherSuiteConfigurations);
        OsDefaultCipherSuiteConfigurations = new ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>(uiWindowsDocumentationCipherSuiteConfigurations);
    }

    private async Task FetchOnlineCipherSuiteInfo(List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        //Ciphersuite[] onlineCipherSuiteInfo = await cipherSuiteInfoApiService.GetAllCipherSuites(cancellationToken);

        var newOnlineCipherSuiteInfos = new List<Ciphersuite?>();

        foreach (WindowsDocumentationCipherSuiteConfiguration windowsDocumentationCipherSuiteConfiguration in windowsDocumentationCipherSuiteConfigurations)
        {
            Ciphersuite? onlineCipherSuiteInfo1 = await cipherSuiteInfoApiService.GetCipherSuite(windowsDocumentationCipherSuiteConfiguration.CipherSuite.ToString(), cancellationToken);

            if (onlineCipherSuiteInfo1 is not null)
                newOnlineCipherSuiteInfos.Add(onlineCipherSuiteInfo1);
        }

        onlineCipherSuiteInfos.Clear();
        //onlineCipherSuiteInfos.AddRange(onlineCipherSuiteInfo.Cast<Ciphersuite?>());
        onlineCipherSuiteInfos.AddRange(newOnlineCipherSuiteInfos);
    }
}