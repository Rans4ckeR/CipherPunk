namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.ComponentModel;
using System.Windows.Media.Imaging;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using CommunityToolkit.Mvvm.Messaging.Messages;

internal abstract class BaseViewModel : ObservableRecipient
{
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private bool defaultCommandActive;
    private bool canExecuteDefaultCommand;
    private BitmapSource? uacIcon;
    private bool? elevated;
    private bool fetchOnlineInfo = true;

    protected BaseViewModel(ILogger logger, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(StrongReferenceMessenger.Default)
    {
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
        UacService = uacService;
        IsActive = true;
        Logger = logger;
        DefaultCommand = new AsyncRelayCommand<bool?>(ExecuteDefaultCommandAsync, _ => CanExecuteDefaultCommand);
        PropertyChanged += BaseViewModelPropertyChanged;

        StrongReferenceMessenger.Default.Register<PropertyChangedMessage<bool>>(this, (r, m) => ((BaseViewModel)r).Receive(m));
    }

    public IAsyncRelayCommand DefaultCommand { get; }

    public bool DefaultCommandActive
    {
        get => defaultCommandActive;
        set
        {
            if (SetProperty(ref defaultCommandActive, value))
                DefaultCommand.NotifyCanExecuteChanged();
        }
    }

    public BitmapSource UacIcon => uacIcon ??= UacService.GetShieldIcon();

    public bool FetchOnlineInfo
    {
        get => fetchOnlineInfo;
        set => _ = SetProperty(ref fetchOnlineInfo, value);
    }

    protected bool Elevated => elevated ??= UacService.GetIntegrityLevel().Elevated;

    protected ILogger Logger { get; }

    protected IUacService UacService { get; }

    protected FrozenDictionary<string, CipherSuite> OnlineCipherSuiteInfos { get; private set; } = FrozenDictionary<string, CipherSuite>.Empty;

    protected bool CanExecuteDefaultCommand
    {
        get => canExecuteDefaultCommand;
        private set
        {
            if (SetProperty(ref canExecuteDefaultCommand, value))
                DefaultCommand.NotifyCanExecuteChanged();
        }
    }

    protected abstract Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken);

    protected virtual void Receive(PropertyChangedMessage<bool> message)
    {
    }

    protected virtual void BaseViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(DefaultCommandActive):
                {
                    UpdateCanExecuteDefaultCommand();
                    break;
                }
        }
    }

    protected virtual bool GetCanExecuteDefaultCommand() => !DefaultCommandActive;

    protected void UpdateCanExecuteDefaultCommand() => CanExecuteDefaultCommand = GetCanExecuteDefaultCommand();

    protected async ValueTask FetchOnlineCipherSuiteInfoAsync(CancellationToken cancellationToken)
    {
        if (!FetchOnlineInfo)
            return;

        OnlineCipherSuiteInfos = await cipherSuiteInfoApiService.GetAllCipherSuitesAsync(true, cancellationToken);
    }

    private async Task ExecuteDefaultCommandAsync(bool? showView, CancellationToken cancellationToken)
    {
        try
        {
            DefaultCommandActive = true;

            await DoExecuteDefaultCommandAsync(cancellationToken);

            if (showView ?? true)
                _ = StrongReferenceMessenger.Default.Send(new ActiveViewValueChangedMessage(this));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Ignore Task cancellation
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
        finally
        {
            DefaultCommandActive = false;
        }
    }
}