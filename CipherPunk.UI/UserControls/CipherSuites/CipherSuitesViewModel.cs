namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

internal sealed class CipherSuitesViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = [];
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private bool fetchOnlineInfo = true;

    public CipherSuitesViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IUacService uacService)
        : base(logger, uacService)
    {
        this.cipherSuiteService = cipherSuiteService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;

        UpdateCanExecuteDefaultCommand();
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

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        FrozenSet<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        FrozenSet<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

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
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security))
            .OrderBy(q => q.Priority);

        ActiveCipherSuiteConfigurations = new(uiWindowsApiCipherSuiteConfigurations);
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.CipherSuite.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}