namespace CipherPunk.UI;

using System.Collections.Frozen;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

internal abstract class BaseCipherSuitesSettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseSettingsViewModel<WindowsApiCipherSuiteConfiguration, UiWindowsApiCipherSuiteConfiguration, UiWindowsDocumentationCipherSuiteConfiguration, UiWindowsDocumentationCipherSuiteConfiguration>(logger, uacService)
{
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = [];
    private bool fetchOnlineInfo = true;

    public bool FetchOnlineInfo
    {
        get => fetchOnlineInfo;
        set => _ = SetProperty(ref fetchOnlineInfo, value);
    }

    protected ICipherSuiteService CipherSuiteService { get; } = cipherSuiteService;

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        FrozenSet<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = CipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        IEnumerable<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = GetActiveSettingConfiguration();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        IEnumerable<UiWindowsApiCipherSuiteConfiguration> uiWindowsApiCipherSuiteConfigurations = windowsApiActiveCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
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
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security));
        IOrderedEnumerable<UiWindowsDocumentationCipherSuiteConfiguration> defaultUiWindowsDocumentationCipherSuiteConfigurations = windowsDocumentationCipherSuiteConfigurations.Select(q => new UiWindowsDocumentationCipherSuiteConfiguration(
            q.Priority,
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
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security))
            .OrderBy(q => q.Priority);

        DefaultSettingConfigurations = new(defaultUiWindowsDocumentationCipherSuiteConfigurations);
        ActiveSettingConfigurations = new(uiWindowsApiCipherSuiteConfigurations);
        ModifiedSettingConfigurations = new(ActiveSettingConfigurations);
    }

    protected override bool CompareSetting(UiWindowsApiCipherSuiteConfiguration uiApiSettingConfiguration, UiWindowsDocumentationCipherSuiteConfiguration uiDocumentationSettingConfiguration)
        => uiApiSettingConfiguration.Id == uiDocumentationSettingConfiguration.CipherSuite;

    protected override UiWindowsApiCipherSuiteConfiguration ConvertSettingCommand(UiWindowsDocumentationCipherSuiteConfiguration availableSettingConfiguration)
    {
        WindowsApiCipherSuiteConfiguration windowsApiCipherSuiteConfiguration = CipherSuiteService.GetOperatingSystemDefaultCipherSuiteList().Single(q => q.CipherSuite == availableSettingConfiguration.CipherSuite);

        return new(
            (ushort)(ModifiedSettingConfigurations!.Count + 1),
            windowsApiCipherSuiteConfiguration.CipherSuite,
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.SSL2_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.SSL3_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.KeyType,
            windowsApiCipherSuiteConfiguration.Certificate,
            windowsApiCipherSuiteConfiguration.MaximumExchangeLength,
            windowsApiCipherSuiteConfiguration.MinimumExchangeLength,
            windowsApiCipherSuiteConfiguration.Exchange,
            windowsApiCipherSuiteConfiguration.HashLength,
            windowsApiCipherSuiteConfiguration.Hash,
            windowsApiCipherSuiteConfiguration.CipherBlockLength,
            windowsApiCipherSuiteConfiguration.CipherLength,
            windowsApiCipherSuiteConfiguration.Cipher,
            onlineCipherSuiteInfos.SingleOrDefault(r => windowsApiCipherSuiteConfiguration.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security);
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => q.CipherSuite).Distinct().Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}