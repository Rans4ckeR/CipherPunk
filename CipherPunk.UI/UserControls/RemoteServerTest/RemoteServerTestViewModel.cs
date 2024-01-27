namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;

internal sealed class RemoteServerTestViewModel : BaseViewModel
{
    private readonly ITlsService tlsService;

    private string? hostName;
    private ushort? port;
    private ObservableCollection<UiRemoteServerTestResult>? remoteServerTestResults;

    public RemoteServerTestViewModel(ILogger logger, ITlsService tlsService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.tlsService = tlsService;
        RunTestCommand = new AsyncRelayCommand(ExecuteRunTestCommandAsync, CanExecuteRunTestCommand);
        Port = 443;

        UpdateCanExecuteDefaultCommand();
    }

    public string? HostName
    {
        get => hostName;
        set
        {
            if (SetProperty(ref hostName, value))
                RunTestCommand.NotifyCanExecuteChanged();
        }
    }

    public ushort? Port
    {
        get => port;
        set
        {
            if (SetProperty(ref port, value))
                RunTestCommand.NotifyCanExecuteChanged();
        }
    }

    public IAsyncRelayCommand RunTestCommand { get; }

    public ObservableCollection<UiRemoteServerTestResult>? RemoteServerTestResults
    {
        get => remoteServerTestResults;
        private set => _ = SetProperty(ref remoteServerTestResults, value);
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
        FrozenSet<(TlsVersion TlsVersion, FrozenSet<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)> remoteServerCipherSuites =
            await tlsService.GetRemoteServerCipherSuitesAsync(HostName!, Port!.Value, cancellationToken);
        IOrderedEnumerable<UiRemoteServerTestResult> uiRemoteServerTestResults = remoteServerCipherSuites.SelectMany(q => q.Results!.Select(r => new UiRemoteServerTestResult(
            q.TlsVersion,
            q.TlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION ? ((SslCipherSuite)r.CipherSuiteId).ToString() : ((TlsCipherSuite)r.CipherSuiteId).ToString(),
            r.Supported,
            r.ErrorReason)))
            .OrderByDescending(q => q.Supported)
            .ThenByDescending(q => q.TlsVersion)
            .ThenBy(q => q.CipherSuiteId);

        RemoteServerTestResults = new(uiRemoteServerTestResults);
    }

    private bool CanExecuteRunTestCommand() => !string.IsNullOrWhiteSpace(HostName) && Port.HasValue;
}