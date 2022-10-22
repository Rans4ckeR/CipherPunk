namespace RS.Schannel.Manager.UI;

using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using Windows.Win32;
using RS.Schannel.Manager.CipherSuiteInfoApi;
using Microsoft.Extensions.Logging;
using RS.Schannel.Manager.API;

internal sealed class CipherSuitesViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly IUacIconService uacIconService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly ITlsService tlsService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = new();
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? osDefaultCipherSuiteConfigurations;
    private ObservableCollection<CipherSuiteConfiguration>? cipherSuiteConfigurations;
    private BitmapSource? uacIcon;
    private bool fetchOnlineInfo = true;

    public CipherSuitesViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IGroupPolicyService groupPolicyService, ITlsService tlsService)
        : base(logger)
    {
        this.cipherSuiteService = cipherSuiteService;
        this.uacIconService = uacIconService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
        this.groupPolicyService = groupPolicyService;
        this.tlsService = tlsService;

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
        //var ffff = await groupPolicyService.GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(cancellationToken);
        List<WindowsApiCipherSuiteConfiguration> windowsApiDefaultActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemDefaultCipherSuiteList();
        //await tlsService.GetRemoteServerCipherSuitesAsync("binfo.bio.wzw.tum.de", cancellationToken); // SSL2 "binfo.bio.wzw.tum.de"

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

        List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        List<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        ushort priority = 0;
        var uiWindowsApiCipherSuiteConfigurations = windowsApiActiveCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
            ++priority,
            q.Protocols.Contains(SslProviderProtocolId.SSL2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.SSL3_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION),
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
            q.Protocols.Contains(SslProviderProtocolId.SSL2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.SSL3_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION),
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