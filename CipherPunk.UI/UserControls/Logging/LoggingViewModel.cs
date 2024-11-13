using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class LoggingViewModel : BaseViewModel
{
    private readonly ISchannelLogService schannelLogService;

    public LoggingViewModel(ILogger logger, ISchannelLogService schannelLogService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.schannelLogService = schannelLogService;

        UpdateCanExecuteDefaultCommand();
    }

    public string? AdminMessage => Elevated ? null : "Run as Administrator to see the logs.";

    public ObservableCollection<SchannelLog>? Logs
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        Logs = Elevated ? new(schannelLogService.GetSchannelLogs().OrderByDescending(q => q.TimeGenerated)) : [];

        return Task.CompletedTask;
    }
}