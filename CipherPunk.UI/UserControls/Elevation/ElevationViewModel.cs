namespace CipherPunk.UI;

using System.Collections.ObjectModel;

internal sealed class ElevationViewModel : BaseViewModel
{
    private ObservableCollection<MandatoryLevel>? mandatoryLevels;
    private MandatoryLevel? mandatoryLevel;

    public ElevationViewModel(ILogger logger, IUacService uacService)
        : base(logger, uacService)
        => UpdateCanExecuteDefaultCommand();

    public ObservableCollection<MandatoryLevel>? MandatoryLevels
    {
        get => mandatoryLevels;
        private set => _ = SetProperty(ref mandatoryLevels, value);
    }

    public MandatoryLevel? MandatoryLevel
    {
        get => mandatoryLevel;
        private set => _ = SetProperty(ref mandatoryLevel, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        MandatoryLevels ??= new(Enum.GetValues<MandatoryLevel>().OrderByDescending(q => (int)q));
        (MandatoryLevel, _) = UacService.GetIntegrityLevel();

        return Task.CompletedTask;
    }
}