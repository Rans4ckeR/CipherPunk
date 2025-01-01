using System.Windows;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using CommunityToolkit.Mvvm.Messaging;

namespace CipherPunk.UI;

internal sealed class MainWindowViewModel : BaseViewModel
{
    private const double OpacityOverlay = 0.75;
    private const double OpacityNoOverlay = 1d;
    private const int ZIndexOverlay = 1;
    private const int ZIndexNoOverlay = -1;

    public MainWindowViewModel(
        ILogger logger,
        IUacService uacService,
        ICipherSuiteInfoApiService cipherSuiteInfoApiService,
        OverviewViewModel overviewViewModel,
        CipherSuitesViewModel cipherSuitesViewModel,
        CipherSuitesOsSettingsViewModel cipherSuitesOsSettingsViewModel,
        CipherSuitesGroupPolicySettingsViewModel cipherSuitesGroupPolicySettingsViewModel,
        EllipticCurvesViewModel ellipticCurvesViewModel,
        EllipticCurvesOsSettingsViewModel ellipticCurvesOsSettingsViewModel,
        EllipticCurvesGroupPolicySettingsViewModel ellipticCurvesGroupPolicySettingsViewModel,
        RemoteServerTestViewModel remoteServerTestViewModel,
        LoggingViewModel loggingViewModel,
        DefaultProtocolsViewModel defaultProtocolsViewModel,
        DefaultCipherSuitesViewModel defaultCipherSuitesViewModel,
        DefaultEllipticCurvesViewModel defaultEllipticCurvesViewModel,
        ElevationViewModel elevationViewModel)
        : base(logger, uacService, cipherSuiteInfoApiService)
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
        DefaultProtocolsViewModel = defaultProtocolsViewModel;
        DefaultCipherSuitesViewModel = defaultCipherSuitesViewModel;
        DefaultEllipticCurvesViewModel = defaultEllipticCurvesViewModel;
        ElevationViewModel = elevationViewModel;
        CopyMessageCommand = new RelayCommand(ExecuteCopyMessageCommand);
        CloseMessageCommand = new RelayCommand(ExecuteCloseMessageCommand);

        StrongReferenceMessenger.Default.Register<UserMessageValueChangedMessage>(this, static (r, m) => ((MainWindowViewModel)r).UserMessage = m.Value.Message);
        StrongReferenceMessenger.Default.Register<ActiveViewValueChangedMessage>(this, static (r, m) => ((MainWindowViewModel)r).ActiveView = m.Value);
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

    public DefaultProtocolsViewModel DefaultProtocolsViewModel { get; }

    public DefaultCipherSuitesViewModel DefaultCipherSuitesViewModel { get; }

    public DefaultEllipticCurvesViewModel DefaultEllipticCurvesViewModel { get; }

    public ElevationViewModel ElevationViewModel { get; }

    public double MainContentOpacity { get; set => _ = SetProperty(ref field, value); } = OpacityNoOverlay;

    public bool MainContentIsHitTestVisible { get; set => _ = SetProperty(ref field, value); } = true;

    public int MessageZIndex { get; set => _ = SetProperty(ref field, value); } = ZIndexNoOverlay;

    public string? UserMessage
    {
        get;
        private set
        {
            if (!SetProperty(ref field, value))
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
        get;
        private set => _ = SetProperty(ref field, value);
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