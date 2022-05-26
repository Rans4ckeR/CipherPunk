﻿namespace RS.Schannel.Manager.UI;

using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;
using Microsoft.Extensions.Logging;

internal sealed class MainWindowViewModel : BaseViewModel
{
    private const double OpacityOverlay = 0.75;
    private const double OpacityNoOverlay = 1d;
    private const int ZIndexOverlay = 1;
    private const int ZIndexNoOverlay = -1;

    private ObservableObject? activeView;
    private string? userMessage;
    private double mainContentOpacity = OpacityNoOverlay;
    private bool mainContentIsHitTestVisible = true;
    private int messageZIndex = ZIndexNoOverlay;

    public MainWindowViewModel(ILogger logger, CipherSuitesViewModel cipherSuitesViewModel)
        : base(logger)
    {
        IsActive = true;
        CipherSuitesViewModel = cipherSuitesViewModel;
        CopyMessageCommand = new RelayCommand(ExecuteCopyMessageCommand);
        CloseMessageCommand = new RelayCommand(ExecuteCloseMessageCommand);

        StrongReferenceMessenger.Default.Register<UserMessageValueChangedMessage>(this, (r, m) =>
        {
            ((MainWindowViewModel)r).UserMessage = m.Value.Message;
        });
        StrongReferenceMessenger.Default.Register<ActiveViewValueChangedMessage>(this, (r, m) =>
        {
            ((MainWindowViewModel)r).ActiveView = m.Value;
        });
        UpdateCanExecuteDefaultCommand();
    }

    public static string Title => "SchannelManager";

    public IRelayCommand CopyMessageCommand { get; }

    public IRelayCommand CloseMessageCommand { get; }

    public CipherSuitesViewModel CipherSuitesViewModel { get; }

    public double MainContentOpacity
    {
        get => mainContentOpacity; set { _ = SetProperty(ref mainContentOpacity, value); }
    }

    public bool MainContentIsHitTestVisible
    {
        get => mainContentIsHitTestVisible; set { _ = SetProperty(ref mainContentIsHitTestVisible, value); }
    }

    public int MessageZIndex
    {
        get => messageZIndex; set { _ = SetProperty(ref messageZIndex, value); }
    }

    public string? UserMessage
    {
        get => userMessage;
        private set
        {
            if (SetProperty(ref userMessage, value))
            {
                if (value is null)
                {
                    MessageZIndex = ZIndexNoOverlay;
                    MainContentOpacity = OpacityNoOverlay;
                    MainContentIsHitTestVisible = true;
                }
                else
                {
                    MessageZIndex = ZIndexOverlay;
                    MainContentOpacity = OpacityOverlay;
                    MainContentIsHitTestVisible = false;
                }
            }
        }
    }

    public ObservableObject? ActiveView
    {
        get => activeView;
        private set => _ = SetProperty(ref activeView, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        ActiveView = null;

        return Task.CompletedTask;
    }

    private void ExecuteCopyMessageCommand()
    {
        Clipboard.SetText(UserMessage);
    }

    private void ExecuteCloseMessageCommand()
    {
        UserMessage = null;
    }
}