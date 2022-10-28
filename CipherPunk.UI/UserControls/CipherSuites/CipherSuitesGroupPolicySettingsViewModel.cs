namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using Windows.Win32;
using CipherPunk.CipherSuiteInfoApi;
using Microsoft.Extensions.Logging;
using CipherPunk;

internal sealed class CipherSuitesGroupPolicySettingsViewModel : BaseViewModel
{
    private readonly ICipherSuiteService cipherSuiteService;
    private readonly IUacIconService uacIconService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly IGroupPolicyService groupPolicyService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = new();
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? activeGroupPolicyCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? defaultGroupPolicyCipherSuiteConfigurations;
    private BitmapSource? uacIcon;
    private bool fetchOnlineInfo = true;
    private string? adminMessage;

    public CipherSuitesGroupPolicySettingsViewModel(ILogger logger, ICipherSuiteService cipherSuiteService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService, IGroupPolicyService groupPolicyService)
        : base(logger)
    {
        this.cipherSuiteService = cipherSuiteService;
        this.uacIconService = uacIconService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
        this.groupPolicyService = groupPolicyService;

        UpdateCanExecuteDefaultCommand();
    }

    public string? AdminMessage
    {
        get => adminMessage;
        private set => _ = SetProperty(ref adminMessage, value);
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

    public ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? ActiveGroupPolicyCipherSuiteConfigurations
    {
        get => activeGroupPolicyCipherSuiteConfigurations;
        private set => _ = SetProperty(ref activeGroupPolicyCipherSuiteConfigurations, value);
    }

    public ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? DefaultGroupPolicyCipherSuiteConfigurations
    {
        get => defaultGroupPolicyCipherSuiteConfigurations;
        private set => _ = SetProperty(ref defaultGroupPolicyCipherSuiteConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        string[] windowsDefaultGroupPolicyCipherSuiteConfigurationsStrings = await groupPolicyService.GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(cancellationToken);
        string[] windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = Array.Empty<string>();

        AdminMessage = null;

        try
        {
            windowsActiveGroupPolicyCipherSuiteConfigurationsStrings = groupPolicyService.GetSslCipherSuiteOrderPolicy();
        }
        catch (UnauthorizedAccessException)
        {
            AdminMessage = "Run as Administrator to see the Group Policy settings.";
        }

        List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDefaultGroupPolicyCipherSuiteConfigurations = windowsDocumentationCipherSuiteConfigurations.Where(q => windowsDefaultGroupPolicyCipherSuiteConfigurationsStrings.Contains(q.CipherSuite.ToString()));
        IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsActiveGroupPolicyCipherSuiteConfigurations = windowsDocumentationCipherSuiteConfigurations.Where(q => windowsActiveGroupPolicyCipherSuiteConfigurationsStrings.Contains(q.CipherSuite.ToString()));

        ushort priority = 0;
        var uiWindowsActiveGroupPolicyCipherSuiteConfigurations = windowsActiveGroupPolicyCipherSuiteConfigurations.Select(q => new UiWindowsDocumentationCipherSuiteConfiguration(
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

        priority = 0;

        var uiWindowsDefaultGroupPolicyCipherSuiteConfigurations = windowsDefaultGroupPolicyCipherSuiteConfigurations.Select(q => new UiWindowsDocumentationCipherSuiteConfiguration(
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

        ActiveGroupPolicyCipherSuiteConfigurations = new(uiWindowsActiveGroupPolicyCipherSuiteConfigurations);
        DefaultGroupPolicyCipherSuiteConfigurations = new(uiWindowsDefaultGroupPolicyCipherSuiteConfigurations);
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.CipherSuite.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}