namespace CipherPunk.UI;

using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;

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

    public MainWindowViewModel(
        ILogger logger,
        IUacService uacService,
        OverviewViewModel overviewViewModel,
        CipherSuitesViewModel cipherSuitesViewModel,
        CipherSuitesOsSettingsViewModel cipherSuitesOsSettingsViewModel,
        CipherSuitesGroupPolicySettingsViewModel cipherSuitesGroupPolicySettingsViewModel,
        EllipticCurvesViewModel ellipticCurvesViewModel,
        EllipticCurvesOsSettingsViewModel ellipticCurvesOsSettingsViewModel,
        EllipticCurvesGroupPolicySettingsViewModel ellipticCurvesGroupPolicySettingsViewModel,
        RemoteServerTestViewModel remoteServerTestViewModel,
        LoggingViewModel loggingViewModel)
        : base(logger, uacService)
    {
        IsActive = true;
        OverviewViewModel = overviewViewModel;
        CipherSuitesViewModel = cipherSuitesViewModel;
        CipherSuitesOsSettingsViewModel = cipherSuitesOsSettingsViewModel;
        CipherSuitesGroupPolicySettingsViewModel = cipherSuitesGroupPolicySettingsViewModel;
        EllipticCurvesViewModel = ellipticCurvesViewModel;
        EllipticCurvesOsSettingsViewModel = ellipticCurvesOsSettingsViewModel;
        EllipticCurvesGroupPolicySettingsViewModel = ellipticCurvesGroupPolicySettingsViewModel;
        RemoteServerTestViewModel = remoteServerTestViewModel;
        LoggingViewModel = loggingViewModel;
        CopyMessageCommand = new RelayCommand(ExecuteCopyMessageCommand);
        CloseMessageCommand = new RelayCommand(ExecuteCloseMessageCommand);

        StrongReferenceMessenger.Default.Register<UserMessageValueChangedMessage>(this, (r, m) => ((MainWindowViewModel)r).UserMessage = m.Value.Message);
        StrongReferenceMessenger.Default.Register<ActiveViewValueChangedMessage>(this, (r, m) => ((MainWindowViewModel)r).ActiveView = m.Value);
        UpdateCanExecuteDefaultCommand();
    }

    public static string Title => "CipherPunk";

    public IRelayCommand CopyMessageCommand { get; }

    public IRelayCommand CloseMessageCommand { get; }

    public OverviewViewModel OverviewViewModel { get; }

    public CipherSuitesViewModel CipherSuitesViewModel { get; }

    public CipherSuitesOsSettingsViewModel CipherSuitesOsSettingsViewModel { get; }

    public CipherSuitesGroupPolicySettingsViewModel CipherSuitesGroupPolicySettingsViewModel { get; }

    public EllipticCurvesViewModel EllipticCurvesViewModel { get; }

    public EllipticCurvesOsSettingsViewModel EllipticCurvesOsSettingsViewModel { get; }

    public EllipticCurvesGroupPolicySettingsViewModel EllipticCurvesGroupPolicySettingsViewModel { get; }

    public RemoteServerTestViewModel RemoteServerTestViewModel { get; }

    public LoggingViewModel LoggingViewModel { get; }

    public double MainContentOpacity
    {
        get => mainContentOpacity; set => _ = SetProperty(ref mainContentOpacity, value);
    }

    public bool MainContentIsHitTestVisible
    {
        get => mainContentIsHitTestVisible; set => _ = SetProperty(ref mainContentIsHitTestVisible, value);
    }

    public int MessageZIndex
    {
        get => messageZIndex; set => _ = SetProperty(ref messageZIndex, value);
    }

    public string? UserMessage
    {
        get => userMessage;
        private set
        {
            if (!SetProperty(ref userMessage, value))
                return;

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
        if (UserMessage is not null)
            Clipboard.SetText(UserMessage);
        else
            Clipboard.Clear();
    }

    private void ExecuteCloseMessageCommand() => UserMessage = null;
}