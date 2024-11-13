using System.Collections.Frozen;
using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

namespace CipherPunk.UI;

internal sealed class CipherSuitesViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;

    public CipherSuitesViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IUacService uacService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.cipherSuiteService = cipherSuiteService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? ActiveCipherSuiteConfigurations
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
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

        ActiveCipherSuiteConfigurations = [.. uiWindowsApiCipherSuiteConfigurations];
    }
}