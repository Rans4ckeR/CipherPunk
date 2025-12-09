using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

namespace CipherPunk.UI;

internal sealed class OverviewViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly IEllipticCurveService ellipticCurveService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly ISchannelService schannelService;

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
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public string? GroupPolicyEllipticCurveMessage
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<SchannelKeyExchangeAlgorithmSettings>? KeyExchangeAlgorithmSettings
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<SchannelCipherSettings>? CipherSettings
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<SchannelHashSettings>? HashSettings
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? ActiveCipherSuiteConfigurations
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? ActiveEllipticCurveConfigurations
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        IReadOnlyCollection<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings = schannelService.GetKeyExchangeAlgorithmSettings();
        IReadOnlyCollection<SchannelCipherSettings> schannelCipherSettings = schannelService.GetSchannelCipherSettings();
        IReadOnlyCollection<SchannelHashSettings> schannelHashSettings = schannelService.GetSchannelHashSettings();

        KeyExchangeAlgorithmSettings = [.. schannelKeyExchangeAlgorithmSettings];
        CipherSettings = [.. schannelCipherSettings];
        HashSettings = [.. schannelHashSettings];
        await SchannelProtocolSettingsViewModel.DefaultCommand.ExecuteAsync(null).ConfigureAwait(ConfigureAwaitOptions.ContinueOnCapturedContext);
        await SchannelSettingsViewModel.DefaultCommand.ExecuteAsync(null).ConfigureAwait(ConfigureAwaitOptions.ContinueOnCapturedContext);

        IReadOnlyCollection<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

        await FetchOnlineCipherSuiteInfoAsync(cancellationToken).ConfigureAwait(true);

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
            .OrderBy(static q => q.Priority);

        ActiveCipherSuiteConfigurations = [.. uiWindowsApiCipherSuiteConfigurations];

        IReadOnlyCollection<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
        IOrderedEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(static q => new UiWindowsApiEllipticCurveConfiguration(
            q.Priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)))
            .OrderBy(static q => q.Priority);

        ActiveEllipticCurveConfigurations = [.. uiWindowsApiEllipticCurveConfigurations];

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