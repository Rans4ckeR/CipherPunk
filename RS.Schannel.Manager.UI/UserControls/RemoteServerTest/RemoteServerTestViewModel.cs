namespace RS.Schannel.Manager.UI;

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using RS.Schannel.Manager.API;

internal sealed class RemoteServerTestViewModel : BaseViewModel
{
    private readonly ITlsService tlsService;

    private string? hostName;
    private ObservableCollection<UiRemoteServerTestResult>? remoteServerTestResults;

    public RemoteServerTestViewModel(ILogger logger, ITlsService tlsService)
        : base(logger)
    {
        this.tlsService = tlsService;
        RunTestCommand = new AsyncRelayCommand(ExecuteRunTestCommandAsync, CanExecuteRunTestCommand);

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

    public IAsyncRelayCommand RunTestCommand { get; }

    public ObservableCollection<UiRemoteServerTestResult>? RemoteServerTestResults
    {
        get => remoteServerTestResults;
        private set => _ = SetProperty(ref remoteServerTestResults, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }

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
        List<(TlsVersion TlsVersion, List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>? Results)> remoteServerCipherSuites = await tlsService.GetRemoteServerCipherSuitesAsync(HostName!, cancellationToken);
        var uiRemoteServerTestResults = remoteServerCipherSuites.SelectMany(q => q.Results!.Select(r => new UiRemoteServerTestResult(
            q.TlsVersion,
            q.TlsVersion is TlsVersion.SSL2_PROTOCOL_VERSION ? ((SslCipherSuites)r.CipherSuiteId).ToString() : ((TlsCipherSuites)r.CipherSuiteId).ToString(),
            r.Supported,
            r.ErrorReason?.Description.ToString()))).ToList();

        RemoteServerTestResults = new(uiRemoteServerTestResults);
    }

    private bool CanExecuteRunTestCommand()
    {
        return !string.IsNullOrWhiteSpace(HostName);
    }
}