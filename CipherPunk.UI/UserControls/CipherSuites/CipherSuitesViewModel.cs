namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using Windows.Win32;
using CipherPunk.CipherSuiteInfoApi;

internal sealed class CipherSuitesViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = new();
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private bool fetchOnlineInfo = true;

    public CipherSuitesViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger)
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
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.CipherSuite.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}