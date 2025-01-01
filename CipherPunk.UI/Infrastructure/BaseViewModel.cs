using System.Collections.Frozen;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Windows.Media.Imaging;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using CommunityToolkit.Mvvm.Messaging.Messages;

namespace CipherPunk.UI;

internal abstract class BaseViewModel : ObservableRecipient
{
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private bool? elevated;

    protected BaseViewModel(ILogger logger, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(StrongReferenceMessenger.Default)
    {
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
        UacService = uacService;
        IsActive = true;
        Logger = logger;
        DefaultCommand = new AsyncRelayCommand<bool?>(ExecuteDefaultCommandAsync, _ => CanExecuteDefaultCommand);
        PropertyChanged += BaseViewModelPropertyChanged;

        StrongReferenceMessenger.Default.Register<PropertyChangedMessage<bool>>(this, static (r, m) => ((BaseViewModel)r).Receive(m));
    }

    public IAsyncRelayCommand DefaultCommand { get; }

    public bool DefaultCommandActive
    {
        get;
        set
        {
            if (SetProperty(ref field, value))
                DefaultCommand.NotifyCanExecuteChanged();
        }
    }

    [field: AllowNull]
    [field: MaybeNull]
    public BitmapSource UacIcon => field ??= UacService.GetShieldIcon();

    public bool FetchOnlineInfo { get; set => _ = SetProperty(ref field, value); } = true;

    protected bool Elevated => elevated ??= UacService.GetIntegrityLevel().Elevated;

    protected ILogger Logger { get; }

    protected IUacService UacService { get; }

    protected FrozenDictionary<string, CipherSuite> OnlineCipherSuiteInfos { get; private set; } = FrozenDictionary<string, CipherSuite>.Empty;

    protected bool CanExecuteDefaultCommand
    {
        get;
        private set
        {
            if (SetProperty(ref field, value))
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