namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.Security;

internal sealed class LoggingViewModel : BaseViewModel
{
    private readonly ISchannelLogService schannelLogService;
    private ObservableCollection<SchannelLog>? logs;
    private string? adminMessage;

    public LoggingViewModel(ILogger logger, ISchannelLogService schannelLogService)
        : base(logger)
    {
        this.schannelLogService = schannelLogService;

        UpdateCanExecuteDefaultCommand();
    }

    public string? AdminMessage
    {
        get => adminMessage;
        private set => _ = SetProperty(ref adminMessage, value);
    }

    public ObservableCollection<SchannelLog>? Logs
    {
        get => logs;
        private set => _ = SetProperty(ref logs, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        AdminMessage = null;

        List<SchannelLog> schannelLogs = [];

        try
        {
            schannelLogs = schannelLogService.GetSchannelLogs();
        }
        catch (SecurityException)
        {
            AdminMessage = "Run as Administrator to see the logs.";
        }

        Logs = new(schannelLogs);

        return Task.CompletedTask;
    }
}