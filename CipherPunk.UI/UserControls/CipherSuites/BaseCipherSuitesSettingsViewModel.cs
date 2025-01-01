using System.Collections.Frozen;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

namespace CipherPunk.UI;

internal abstract class BaseCipherSuitesSettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseSettingsViewModel<WindowsApiCipherSuiteConfiguration, UiWindowsApiCipherSuiteConfiguration, UiWindowsDocumentationCipherSuiteConfiguration, UiWindowsDocumentationCipherSuiteConfiguration>(logger, uacService, cipherSuiteInfoApiService)
{
    protected ICipherSuiteService CipherSuiteService { get; } = cipherSuiteService;

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        FrozenSet<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = CipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        IEnumerable<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = GetActiveSettingConfiguration();

        await FetchOnlineCipherSuiteInfoAsync(cancellationToken);

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
            OnlineCipherSuiteInfos.TryGetValue(q.CipherSuite.ToString(), out CipherSuite cipherSuite) ? cipherSuite.Security : null));
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
            OnlineCipherSuiteInfos.TryGetValue(q.CipherSuite.ToString(), out CipherSuite cipherSuite) ? cipherSuite.Security : null))
            .OrderBy(static q => q.Priority);

        DefaultSettingConfigurations = [.. defaultUiWindowsDocumentationCipherSuiteConfigurations];
        ActiveSettingConfigurations = [.. uiWindowsApiCipherSuiteConfigurations];
        ModifiedSettingConfigurations = [.. ActiveSettingConfigurations];
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
            OnlineCipherSuiteInfos.TryGetValue(windowsApiCipherSuiteConfiguration.CipherSuite.ToString(), out CipherSuite cipherSuite) ? cipherSuite.Security : null);
    }
}