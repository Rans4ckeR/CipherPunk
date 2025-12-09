using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;

namespace CipherPunk.UI;

internal sealed class SchannelSettingsViewModel : BaseViewModel
{
    private readonly ISchannelService schannelService;

    public SchannelSettingsViewModel(ISchannelService schannelService, ILogger logger, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.schannelService = schannelService;
        SaveSettingsCommand = new AsyncRelayCommand(DoExecuteSaveSettingsCommand, CanExecuteSaveSettingsCommand);
        ResetSettingsCommand = new AsyncRelayCommand(DoExecuteResetSettingsCommand, CanExecuteResetSettingsCommand);
        CancelSettingsCommand = new AsyncRelayCommand(DoExecuteCancelSettingsCommand, CanExecuteCancelSettingsCommand);

        UpdateCanExecuteDefaultCommand();
    }

    public IAsyncRelayCommand SaveSettingsCommand { get; }

    public IAsyncRelayCommand ResetSettingsCommand { get; }

    public IAsyncRelayCommand CancelSettingsCommand { get; }

    public UiSchannelSettings? SchannelSettings
    {
        get;
        set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        SchannelSettings = new(schannelService.GetSchannelSettings());

        return Task.CompletedTask;
    }

    private static bool CanExecuteCancelSettingsCommand()
        => true;

    private async Task DoExecuteSaveSettingsCommand()
    {
        schannelService.UpdateSchannelSettings(new(
            (SchannelEventLogging)SchannelSettings!.EventLogging!.Where(static q => q.Enabled).Sum(static q => (int)q.Member),
            (SchannelCertificateMappingMethod)SchannelSettings!.CertificateMappingMethods!.Where(static q => q.Enabled).Sum(static q => (int)q.Member),
            SchannelSettings!.ClientCacheTime,
            SchannelSettings!.EnableOcspStaplingForSni,
            SchannelSettings!.IssuerCacheSize,
            SchannelSettings!.IssuerCacheTime,
            SchannelSettings!.MaximumCacheSize,
            SchannelSettings!.SendTrustedIssuerList,
            SchannelSettings!.ServerCacheTime,
            SchannelSettings!.MessageLimitClient,
            SchannelSettings!.MessageLimitServer,
            SchannelSettings!.MessageLimitServerClientAuth));
        await DoExecuteDefaultCommandAsync(CancellationToken.None).ConfigureAwait(ConfigureAwaitOptions.ContinueOnCapturedContext);
        NotifyCanExecuteChanged();
    }

    private async Task DoExecuteResetSettingsCommand()
    {
        schannelService.ResetSchannelSettings();
        await DoExecuteDefaultCommandAsync(CancellationToken.None).ConfigureAwait(ConfigureAwaitOptions.ContinueOnCapturedContext);
        NotifyCanExecuteChanged();
    }

    private async Task DoExecuteCancelSettingsCommand()
    {
        await DoExecuteDefaultCommandAsync(CancellationToken.None).ConfigureAwait(ConfigureAwaitOptions.ContinueOnCapturedContext);
        NotifyCanExecuteChanged();
    }

    private bool CanExecuteSaveSettingsCommand()
        => Elevated;

    private bool CanExecuteResetSettingsCommand()
        => Elevated;

    private void NotifyCanExecuteChanged()
    {
        SaveSettingsCommand.NotifyCanExecuteChanged();
        CancelSettingsCommand.NotifyCanExecuteChanged();
        ResetSettingsCommand.NotifyCanExecuteChanged();
    }
}