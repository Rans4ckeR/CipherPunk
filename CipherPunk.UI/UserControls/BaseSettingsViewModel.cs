namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;

internal abstract class BaseSettingsViewModel<TActive, TUserInterface, TAvailable, TDefault> : BaseViewModel
{
    private ObservableCollection<TUserInterface>? activeSettingConfigurations;
    private ObservableCollection<TUserInterface>? modifiedSettingConfigurations;
    private ObservableCollection<TDefault>? defaultSettingConfigurations;

    protected BaseSettingsViewModel(ILogger logger, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        MoveSettingUpCommand = new RelayCommand<TUserInterface?>(ExecuteMoveSettingUpCommand, CanExecuteMoveSettingUpCommand);
        MoveSettingDownCommand = new RelayCommand<TUserInterface?>(ExecuteMoveSettingDownCommand, CanExecuteMoveSettingDownCommand);
        DeleteSettingCommand = new RelayCommand<TUserInterface?>(ExecuteDeleteSettingCommand, CanExecuteDeleteSettingCommand);
        AddSettingCommand = new RelayCommand<TAvailable?>(ExecuteAddSettingCommand, CanExecuteAddSettingCommand);
        SaveSettingsCommand = new AsyncRelayCommand(ExecuteSaveSettingsCommandAsync, CanExecuteSaveSettingsCommand);
        CancelSettingsCommand = new RelayCommand(ExecuteCancelSettingsCommand, CanExecuteCancelSettingsCommand);
        ResetSettingsCommand = new AsyncRelayCommand(ExecuteResetSettingsCommandAsync, CanExecuteResetSettingsCommand);

        UpdateCanExecuteDefaultCommand();
    }

    public IRelayCommand MoveSettingUpCommand { get; }

    public IRelayCommand MoveSettingDownCommand { get; }

    public IRelayCommand DeleteSettingCommand { get; }

    public IRelayCommand AddSettingCommand { get; }

    public IAsyncRelayCommand SaveSettingsCommand { get; }

    public IRelayCommand CancelSettingsCommand { get; }

    public IAsyncRelayCommand ResetSettingsCommand { get; }

    public ObservableCollection<TUserInterface>? ModifiedSettingConfigurations
    {
        get => modifiedSettingConfigurations;
        protected set => _ = SetProperty(ref modifiedSettingConfigurations, value);
    }

    public ObservableCollection<TDefault>? DefaultSettingConfigurations
    {
        get => defaultSettingConfigurations;
        protected set => _ = SetProperty(ref defaultSettingConfigurations, value);
    }

    protected ObservableCollection<TUserInterface>? ActiveSettingConfigurations
    {
        get => activeSettingConfigurations;
        set => _ = SetProperty(ref activeSettingConfigurations, value);
    }

    protected abstract IEnumerable<TActive> GetActiveSettingConfiguration();

    protected abstract void DoExecuteSaveSettingsCommand();

    protected abstract void DoExecuteResetSettingsCommand();

    protected abstract bool CompareSetting(TUserInterface userInterfaceSettingConfiguration, TAvailable availableSettingConfiguration);

    protected abstract TUserInterface ConvertSettingCommand(TAvailable availableSettingConfiguration);

    private bool CanExecuteMoveSettingUpCommand(TUserInterface? userInterfaceSettingConfiguration)
        => Elevated && userInterfaceSettingConfiguration is not null && ModifiedSettingConfigurations!.IndexOf(userInterfaceSettingConfiguration) > 0;

    private bool CanExecuteMoveSettingDownCommand(TUserInterface? userInterfaceSettingConfiguration)
        => Elevated && userInterfaceSettingConfiguration is not null && ModifiedSettingConfigurations!.IndexOf(userInterfaceSettingConfiguration) < ModifiedSettingConfigurations.Count - 1;

    private bool CanExecuteDeleteSettingCommand(TUserInterface? userInterfaceSettingConfiguration)
        => Elevated && userInterfaceSettingConfiguration is not null;

    private bool CanExecuteSaveSettingsCommand()
        => Elevated && !(activeSettingConfigurations?.SequenceEqual(ModifiedSettingConfigurations ?? []) ?? false);

    private bool CanExecuteCancelSettingsCommand()
        => Elevated && !(activeSettingConfigurations?.SequenceEqual(ModifiedSettingConfigurations ?? []) ?? false);

    private bool CanExecuteAddSettingCommand(TAvailable? availableSettingConfiguration)
        => Elevated && availableSettingConfiguration is not null && ModifiedSettingConfigurations!.All(q => !CompareSetting(q, availableSettingConfiguration));

    private bool CanExecuteResetSettingsCommand()
        => Elevated;

    private void ExecuteMoveSettingUpCommand(TUserInterface? userInterfaceSettingConfiguration)
    {
        int index = ModifiedSettingConfigurations!.IndexOf(userInterfaceSettingConfiguration!);

        ModifiedSettingConfigurations.Move(index, --index);
        NotifyCanExecuteChanged();
    }

    private void ExecuteMoveSettingDownCommand(TUserInterface? userInterfaceSettingConfiguration)
    {
        int index = ModifiedSettingConfigurations!.IndexOf(userInterfaceSettingConfiguration!);

        ModifiedSettingConfigurations.Move(index, ++index);
        NotifyCanExecuteChanged();
    }

    private void ExecuteDeleteSettingCommand(TUserInterface? userInterfaceSettingConfiguration)
    {
        _ = ModifiedSettingConfigurations!.Remove(userInterfaceSettingConfiguration!);
        NotifyCanExecuteChanged();
    }

    private void ExecuteAddSettingCommand(TAvailable? availableSettingConfiguration)
    {
        TUserInterface userInterfaceSettingConfiguration = ConvertSettingCommand(availableSettingConfiguration!);

        ModifiedSettingConfigurations!.Add(userInterfaceSettingConfiguration);
        NotifyCanExecuteChanged();
    }

    private async Task ExecuteSaveSettingsCommandAsync()
    {
        DoExecuteSaveSettingsCommand();
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
        NotifyCanExecuteChanged();
    }

    private void ExecuteCancelSettingsCommand()
    {
        ModifiedSettingConfigurations = new(activeSettingConfigurations!);

        NotifyCanExecuteChanged();
    }

    private async Task ExecuteResetSettingsCommandAsync()
    {
        DoExecuteResetSettingsCommand();
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
        NotifyCanExecuteChanged();
    }

    private void NotifyCanExecuteChanged()
    {
        MoveSettingUpCommand.NotifyCanExecuteChanged();
        MoveSettingDownCommand.NotifyCanExecuteChanged();
        SaveSettingsCommand.NotifyCanExecuteChanged();
        CancelSettingsCommand.NotifyCanExecuteChanged();
        AddSettingCommand.NotifyCanExecuteChanged();
        ResetSettingsCommand.NotifyCanExecuteChanged();
    }
}