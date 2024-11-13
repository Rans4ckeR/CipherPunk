using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;

namespace CipherPunk.UI;

internal sealed class SchannelProtocolSettingsViewModel : BaseViewModel
{
    private readonly ISchannelService schannelService;

    public SchannelProtocolSettingsViewModel(ISchannelService schannelService, ILogger logger, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
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

    public ObservableCollection<UiSchannelProtocolSettings>? SchannelProtocolSettings
    {
        get;
        set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        SchannelProtocolSettings = [.. schannelService.GetProtocolSettings().Select(q => new UiSchannelProtocolSettings(q)).OrderByDescending(q => q.Protocol)];

        return Task.CompletedTask;
    }

    private static bool CanExecuteCancelSettingsCommand()
        => true;

    private async Task DoExecuteSaveSettingsCommand()
    {
        schannelService.UpdateProtocolSettings(SchannelProtocolSettings!.Select(q => new SchannelProtocolSettings(q.Protocol, q.ClientStatus, q.ServerStatus)));
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
        NotifyCanExecuteChanged();
    }

    private async Task DoExecuteResetSettingsCommand()
    {
        schannelService.ResetProtocolSettings();
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
        NotifyCanExecuteChanged();
    }

    private async Task DoExecuteCancelSettingsCommand()
    {
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
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