namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

internal sealed class DefaultCipherSuitesViewModel : BaseViewModel
{
    private readonly IWindowsCipherSuiteDocumentationService windowsCipherSuiteDocumentationService;
    private readonly ITlsService tlsService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = [];
    private bool fetchOnlineInfo = true;
    private ObservableCollection<WindowsVersion>? windowsVersions;
    private WindowsVersion? windowsVersion;
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? defaultCipherSuites;

    public DefaultCipherSuitesViewModel(ILogger logger, IWindowsCipherSuiteDocumentationService windowsCipherSuiteDocumentationService, IUacService uacService, ITlsService tlsService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService)
    {
        this.windowsCipherSuiteDocumentationService = windowsCipherSuiteDocumentationService;
        this.tlsService = tlsService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;

        UpdateCanExecuteDefaultCommand();
    }

    public bool FetchOnlineInfo
    {
        get => fetchOnlineInfo;
        set => _ = SetProperty(ref fetchOnlineInfo, value);
    }

    public ObservableCollection<WindowsVersion>? WindowsVersions
    {
        get => windowsVersions;
        private set => _ = SetProperty(ref windowsVersions, value);
    }

    public WindowsVersion? WindowsVersion
    {
        get => windowsVersion;
        set => _ = SetProperty(ref windowsVersion, value);
    }

    public ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? DefaultCipherSuites
    {
        get => defaultCipherSuites;
        private set => _ = SetProperty(ref defaultCipherSuites, value);
    }

    protected override void BaseViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        base.BaseViewModelPropertyChanged(sender, e);

        switch (e.PropertyName)
        {
            case nameof(WindowsVersion):
#pragma warning disable CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
#pragma warning disable IDE0058 // Expression value is never used
                OnWindowsVersionChangedAsync();
#pragma warning restore IDE0058 // Expression value is never used
#pragma warning restore CS4014 // Because this call is not awaited, execution of the current method continues before the call is completed
                break;
        }
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        WindowsVersions ??= new(Enum.GetValues<WindowsVersion>().OrderByDescending(q => (int)q));
        WindowsVersion ??= tlsService.GetWindowsVersion();

        return Task.CompletedTask;
    }

    private async Task OnWindowsVersionChangedAsync()
    {
        try
        {
            List<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = windowsCipherSuiteDocumentationService.GetWindowsDocumentationCipherSuiteConfigurations(WindowsVersion!.Value);

            if (FetchOnlineInfo)
                await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, CancellationToken.None);

            ushort priority = ushort.MinValue;
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

            DefaultCipherSuites = new(uiWindowsDocumentationCipherSuiteConfigurations);
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
    }

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => q.CipherSuite).Distinct().Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }
}