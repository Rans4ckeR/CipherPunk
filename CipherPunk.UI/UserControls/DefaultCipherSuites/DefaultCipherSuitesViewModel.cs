using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;
using Windows.Win32;

namespace CipherPunk.UI;

internal sealed class DefaultCipherSuitesViewModel : BaseViewModel
{
    private readonly IWindowsDocumentationService windowsDocumentationService;
    private readonly IWindowsVersionService windowsVersionService;

    public DefaultCipherSuitesViewModel(ILogger logger, IWindowsDocumentationService windowsDocumentationService, IUacService uacService, IWindowsVersionService windowsVersionService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.windowsDocumentationService = windowsDocumentationService;
        this.windowsVersionService = windowsVersionService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<WindowsVersion>? WindowsVersions
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public WindowsVersion? WindowsVersion
    {
        get;
        set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? DefaultCipherSuites
    {
        get;
        private set => _ = SetProperty(ref field, value);
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
        WindowsVersions ??= [.. Enum.GetValues<WindowsVersion>().OrderByDescending(static q => (int)q)];
        WindowsVersion ??= windowsVersionService.WindowsVersion;

        return Task.CompletedTask;
    }

    private async Task OnWindowsVersionChangedAsync()
    {
        try
        {
            FrozenSet<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = windowsDocumentationService.GetCipherSuiteConfigurations(WindowsVersion!.Value);

            await FetchOnlineCipherSuiteInfoAsync(CancellationToken.None).ConfigureAwait(true);

            IOrderedEnumerable<UiWindowsDocumentationCipherSuiteConfiguration> uiWindowsDocumentationCipherSuiteConfigurations = windowsDocumentationCipherSuiteConfigurations.Select(q => new UiWindowsDocumentationCipherSuiteConfiguration(
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

            DefaultCipherSuites = [.. uiWindowsDocumentationCipherSuiteConfigurations];
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
    }
}