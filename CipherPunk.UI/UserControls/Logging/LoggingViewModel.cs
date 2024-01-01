namespace CipherPunk.UI;

using System.Collections.ObjectModel;

internal sealed class LoggingViewModel : BaseViewModel
{
    private readonly ISchannelLogService schannelLogService;
    private ObservableCollection<SchannelLog>? logs;

    public LoggingViewModel(ILogger logger, ISchannelLogService schannelLogService, IUacService uacService)
        : base(logger, uacService)
    {
        this.schannelLogService = schannelLogService;

        UpdateCanExecuteDefaultCommand();
    }

    public string? AdminMessage => Elevated ? null : "Run as Administrator to see the logs.";

    public ObservableCollection<SchannelLog>? Logs
    {
        get => logs;
        private set => _ = SetProperty(ref logs, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        Logs = Elevated ? new(schannelLogService.GetSchannelLogs()) : [];

        return Task.CompletedTask;
    }
}