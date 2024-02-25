namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

internal sealed class OverviewViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly IEllipticCurveService ellipticCurveService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly ISchannelService schannelService;
    private ObservableCollection<SchannelKeyExchangeAlgorithmSettings>? keyExchangeAlgorithmSettings;
    private ObservableCollection<SchannelCipherSettings>? cipherSettings;
    private ObservableCollection<SchannelHashSettings>? hashSettings;
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? activeEllipticCurveConfigurations;
    private string? groupPolicyCipherSuiteMessage;
    private string? groupPolicyEllipticCurveMessage;

    public OverviewViewModel(
        ILogger logger,
        ISchannelService schannelService,
        ICipherSuiteService cipherSuiteService,
        IEllipticCurveService ellipticCurveService,
        ICipherSuiteInfoApiService cipherSuiteInfoApiService,
        IGroupPolicyService groupPolicyService,
        IUacService uacService,
        SchannelSettingsViewModel schannelSettingsViewModel,
        SchannelProtocolSettingsViewModel schannelProtocolSettingsViewModel)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.schannelService = schannelService;
        this.cipherSuiteService = cipherSuiteService;
        this.ellipticCurveService = ellipticCurveService;
        this.groupPolicyService = groupPolicyService;
        SchannelSettingsViewModel = schannelSettingsViewModel;
        SchannelProtocolSettingsViewModel = schannelProtocolSettingsViewModel;

        UpdateCanExecuteDefaultCommand();
    }

    public SchannelSettingsViewModel SchannelSettingsViewModel { get; }

    public SchannelProtocolSettingsViewModel SchannelProtocolSettingsViewModel { get; }

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
        FrozenSet<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings = schannelService.GetKeyExchangeAlgorithmSettings();
        FrozenSet<SchannelCipherSettings> schannelCipherSettings = schannelService.GetSchannelCipherSettings();
        FrozenSet<SchannelHashSettings> schannelHashSettings = schannelService.GetSchannelHashSettings();

        KeyExchangeAlgorithmSettings = new(schannelKeyExchangeAlgorithmSettings);
        CipherSettings = new(schannelCipherSettings);
        HashSettings = new(schannelHashSettings);
        await SchannelProtocolSettingsViewModel.DefaultCommand.ExecuteAsync(null);
        await SchannelSettingsViewModel.DefaultCommand.ExecuteAsync(null);

        FrozenSet<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

        await FetchOnlineCipherSuiteInfoAsync(cancellationToken);

        IOrderedEnumerable<UiWindowsApiCipherSuiteConfiguration> uiWindowsApiCipherSuiteConfigurations = windowsApiActiveCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
            q.Priority,
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
            OnlineCipherSuiteInfos.TryGetValue(q.CipherSuite.ToString(), out CipherSuite cipherSuite) ? cipherSuite.Security : null))
            .OrderBy(q => q.Priority);

        ActiveCipherSuiteConfigurations = new(uiWindowsApiCipherSuiteConfigurations);

        FrozenSet<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
        IOrderedEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            q.Priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)))
            .OrderBy(q => q.Priority);

        ActiveEllipticCurveConfigurations = new(uiWindowsApiEllipticCurveConfigurations);

        DetectGroupPolicyOverride();
    }

    private void DetectGroupPolicyOverride()
    {
        GroupPolicyCipherSuiteMessage = null;
        GroupPolicyEllipticCurveMessage = null;

        if (!Elevated)
        {
            GroupPolicyCipherSuiteMessage = "Current Cipher Suite settings might be set by Group Policy. Run as Administrator to verify.";
            GroupPolicyEllipticCurveMessage = "Current Elliptic Curve settings might be set by Group Policy. Run as Administrator to verify.";

            return;
        }

        string[] cipherSuiteOrderPolicy = groupPolicyService.GetSslCipherSuiteOrderPolicy();
        string[] eccCurveOrderPolicy = groupPolicyService.GetEccCurveOrderPolicy();

        if (cipherSuiteOrderPolicy.Length > 0)
            GroupPolicyCipherSuiteMessage = "Current Cipher Suite settings are set by Group Policy.";

        if (eccCurveOrderPolicy.Length > 0)
            GroupPolicyEllipticCurveMessage = "Current Elliptic Curve settings are set by Group Policy.";
    }
}