namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

internal sealed class OverviewViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly IEllipticCurveService ellipticCurveService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly ISchannelService schannelService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = new();
    private ObservableCollection<SchannelProtocolSettings>? protocolSettings;
    private ObservableCollection<SchannelKeyExchangeAlgorithmSettings>? keyExchangeAlgorithmSettings;
    private ObservableCollection<SchannelCipherSettings>? cipherSettings;
    private ObservableCollection<SchannelHashSettings>? hashSettings;
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;
    private SchannelSettings? settings;
    private bool fetchOnlineInfo = true;
    private string? groupPolicyCipherSuiteMessage;
    private string? groupPolicyEllipticCurveMessage;

    public OverviewViewModel(ILogger logger, ISchannelService schannelService, ICipherSuiteService cipherSuiteService, IEllipticCurveService ellipticCurveService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IGroupPolicyService groupPolicyService)
        : base(logger)
    {
        this.schannelService = schannelService;
        this.cipherSuiteService = cipherSuiteService;
        this.ellipticCurveService = ellipticCurveService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
        this.groupPolicyService = groupPolicyService;

        UpdateCanExecuteDefaultCommand();
    }

    public bool FetchOnlineInfo
    {
        get => fetchOnlineInfo;
        set => _ = SetProperty(ref fetchOnlineInfo, value);
    }

    public string? GroupPolicyCipherSuiteMessage
    {
        get => groupPolicyCipherSuiteMessage;
        private set => _ = SetProperty(ref groupPolicyCipherSuiteMessage, value);
    }

    public string? GroupPolicyEllipticCurveMessage
    {
        get => groupPolicyEllipticCurveMessage;
        private set => _ = SetProperty(ref groupPolicyEllipticCurveMessage, value);
    }

    public SchannelSettings? Settings
    {
        get => settings;
        private set => _ = SetProperty(ref settings, value);
    }

    public ObservableCollection<SchannelProtocolSettings>? ProtocolSettings
    {
        get => protocolSettings;
        private set => _ = SetProperty(ref protocolSettings, value);
    }

    public ObservableCollection<SchannelKeyExchangeAlgorithmSettings>? KeyExchangeAlgorithmSettings
    {
        get => keyExchangeAlgorithmSettings;
        private set => _ = SetProperty(ref keyExchangeAlgorithmSettings, value);
    }

    public ObservableCollection<SchannelCipherSettings>? CipherSettings
    {
        get => cipherSettings;
        private set => _ = SetProperty(ref cipherSettings, value);
    }

    public ObservableCollection<SchannelHashSettings>? HashSettings
    {
        get => hashSettings;
        private set => _ = SetProperty(ref hashSettings, value);
    }

    public ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? ActiveCipherSuiteConfigurations
    {
        get => activeCipherSuiteConfigurations;
        private set => _ = SetProperty(ref activeCipherSuiteConfigurations, value);
    }

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? ActiveEllipticCurveConfigurations
    {
        get => activeEllipticCurveConfigurations;
        private set => _ = SetProperty(ref activeEllipticCurveConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        List<SchannelProtocolSettings> schannelProtocolSettings = schannelService.GetProtocolSettings();
        List<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings = schannelService.GetKeyExchangeAlgorithmSettings();
        List<SchannelCipherSettings> schannelCipherSettings = schannelService.GetSchannelCipherSettings();
        List<SchannelHashSettings> schannelHashSettings = schannelService.GetSchannelHashSettings();
        SchannelSettings schannelSettings = schannelService.GetSchannelSettings();

        ProtocolSettings = new(schannelProtocolSettings);
        KeyExchangeAlgorithmSettings = new(schannelKeyExchangeAlgorithmSettings);
        CipherSettings = new(schannelCipherSettings);
        HashSettings = new(schannelHashSettings);
        Settings = schannelSettings;

        List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        List<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        ushort priority = 0;
        var uiWindowsApiCipherSuiteConfigurations = windowsApiActiveCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
            ++priority,
            q.CipherSuite,
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
            q.Cipher,
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security)).ToList();

        ActiveCipherSuiteConfigurations = new(uiWindowsApiCipherSuiteConfigurations);

        List<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();

        priority = 0;

        var uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            ++priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(",", q.CngAlgorithms))).ToList();

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);

        DetectGroupPolicyOverride();
    }

    private void DetectGroupPolicyOverride()
    {
        GroupPolicyCipherSuiteMessage = null;
        GroupPolicyEllipticCurveMessage = null;

        try
        {
            string[] cipherSuiteOrderPolicy = groupPolicyService.GetSslCipherSuiteOrderPolicy();
            string[] eccCurveOrderPolicy = groupPolicyService.GetEccCurveOrderPolicy();

            if (cipherSuiteOrderPolicy.Length > 0)
                GroupPolicyCipherSuiteMessage = "Current Cipher Suite settings are set by Group Policy.";

            if (eccCurveOrderPolicy.Length > 0)
                GroupPolicyEllipticCurveMessage = "Current Elliptic Curve settings are set by Group Policy.";
        }
        catch (UnauthorizedAccessException)
        {
            GroupPolicyCipherSuiteMessage = "Current Cipher Suite settings might be set by Group Policy. Run as Administrator to verify.";
            GroupPolicyEllipticCurveMessage = "Current Elliptic Curve settings might be set by Group Policy. Run as Administrator to verify.";
        }
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.CipherSuite.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}