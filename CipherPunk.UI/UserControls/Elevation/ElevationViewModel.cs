using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class ElevationViewModel : BaseViewModel
{
    public ElevationViewModel(ILogger logger, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
        => UpdateCanExecuteDefaultCommand();

    public ObservableCollection<MandatoryLevel>? MandatoryLevels
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public MandatoryLevel? MandatoryLevel
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        MandatoryLevels ??= [.. Enum.GetValues<MandatoryLevel>().OrderByDescending(static q => (int)q)];
        (MandatoryLevel, _) = UacService.GetIntegrityLevel();

        return Task.CompletedTask;
    }
}