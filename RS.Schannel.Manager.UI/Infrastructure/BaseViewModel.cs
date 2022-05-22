namespace RS.Schannel.Manager.UI;

using System.ComponentModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using CommunityToolkit.Mvvm.Messaging.Messages;
using Microsoft.Extensions.Logging;

internal abstract class BaseViewModel : ObservableRecipient
{
    private bool defaultCommandActive;
    private bool canExecuteDefaultCommand;

    protected BaseViewModel(ILogger logger)
        : base(StrongReferenceMessenger.Default)
    {
        IsActive = true;
        Logger = logger;
        DefaultCommand = new AsyncRelayCommand<bool?>(ExecuteDefaultCommandAsync, _ => CanExecuteDefaultCommand);
        PropertyChanged += BaseViewModelPropertyChanged;

        StrongReferenceMessenger.Default.Register<PropertyChangedMessage<bool>>(this, (r, m) =>
        {
            ((BaseViewModel)r).Receive(m);
        });
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

    protected ILogger Logger { get; }

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

    protected virtual bool GetCanExecuteDefaultCommand()
    {
        return !DefaultCommandActive;
    }

    protected void UpdateCanExecuteDefaultCommand()
    {
        CanExecuteDefaultCommand = GetCanExecuteDefaultCommand();
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
        catch (OperationCanceledException)
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