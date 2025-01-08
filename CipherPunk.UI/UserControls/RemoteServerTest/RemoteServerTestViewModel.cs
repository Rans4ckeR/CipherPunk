using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;

namespace CipherPunk.UI;

internal sealed class RemoteServerTestViewModel : BaseViewModel
{
    private readonly ITlsService tlsService;
    private readonly ICipherSuiteService cipherSuiteService;

    public RemoteServerTestViewModel(ILogger logger, ITlsService tlsService, ICipherSuiteService cipherSuiteService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.tlsService = tlsService;
        this.cipherSuiteService = cipherSuiteService;
        RunTestCommand = new AsyncRelayCommand(ExecuteRunTestCommandAsync, CanExecuteRunTestCommand);
        Port = 443;

        UpdateCanExecuteDefaultCommand();
    }

    public string? HostName
    {
        get;
        set
        {
            if (SetProperty(ref field, value))
                RunTestCommand.NotifyCanExecuteChanged();
        }
    }

    public ushort? Port
    {
        get;
        set
        {
            if (SetProperty(ref field, value))
                RunTestCommand.NotifyCanExecuteChanged();
        }
    }

    public IAsyncRelayCommand RunTestCommand { get; }

    public ObservableCollection<UiRemoteServerTestResult>? MatchingActiveCipherSuites
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<UiRemoteServerTestResult>? MatchingInactiveCipherSuites
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<UiRemoteServerTestResult>? NotSupportedCipherSuites
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<UiRemoteServerTestResult>? RemoteServerTestResults
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    protected override void BaseViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        base.BaseViewModelPropertyChanged(sender, e);

        switch (e.PropertyName)
        {
            case nameof(HostName):
                {
                    UpdateCanExecuteDefaultCommand();
                    break;
                }
        }
    }

    private async Task ExecuteRunTestCommandAsync(CancellationToken cancellationToken)
    {
        FrozenSet<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemActiveCipherSuiteList();
        FrozenSet<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = cipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        FrozenSet<(TlsVersion TlsVersion, FrozenSet<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)> remoteServerCipherSuites = await tlsService.GetRemoteServerCipherSuitesAsync(HostName!, Port!.Value, cancellationToken);
        List<UiRemoteServerTestResult> remoteActiveCipherSuiteConfigurations =
        [
            ..remoteServerCipherSuites
                .SelectMany(static q => q.Results!.Select(r => new UiRemoteServerTestResult(
                    q.TlsVersion,
                    q.TlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION ? ((SslCipherSuite)r.CipherSuiteId).ToString() : ((TlsCipherSuite)r.CipherSuiteId).ToString(),
                    r.Supported,
                    r.ErrorReason)))
                .OrderByDescending(static q => q.Supported)
                .ThenByDescending(static q => q.TlsVersion)
                .ThenBy(static q => q.CipherSuiteId)
        ];

        RemoteServerTestResults = [.. remoteActiveCipherSuiteConfigurations];
        MatchingActiveCipherSuites = [.. remoteActiveCipherSuiteConfigurations.Where(q => q.Supported && windowsApiActiveCipherSuiteConfigurations.Select(static r => r.CipherSuite.ToString()).Contains(q.CipherSuiteId))];
        MatchingInactiveCipherSuites = [.. remoteActiveCipherSuiteConfigurations.Where(q => q.Supported && windowsDocumentationCipherSuiteConfigurations.Select(static r => r.CipherSuite.ToString()).Contains(q.CipherSuiteId))];
        NotSupportedCipherSuites = [.. remoteActiveCipherSuiteConfigurations.Where(q => q.Supported && !windowsDocumentationCipherSuiteConfigurations.Select(static r => r.CipherSuite.ToString()).Contains(q.CipherSuiteId))];
    }

    private bool CanExecuteRunTestCommand() => !string.IsNullOrWhiteSpace(HostName) && Port.HasValue;
}