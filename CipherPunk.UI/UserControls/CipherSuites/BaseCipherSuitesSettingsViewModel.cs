namespace CipherPunk.UI;

using System.Collections.ObjectModel;
using System.Windows.Media.Imaging;
using CipherPunk.CipherSuiteInfoApi;
using CommunityToolkit.Mvvm.Input;
using Windows.Win32;

internal abstract class BaseCipherSuitesSettingsViewModel : BaseViewModel
{
    private readonly IUacIconService uacIconService;
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;
    private readonly List<CipherSuite?> onlineCipherSuiteInfos = [];
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? modifiedCipherSuiteConfigurations;
    private ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? defaultCipherSuiteConfigurations;
    private BitmapSource? uacIcon;
    private bool fetchOnlineInfo = true;

    protected BaseCipherSuitesSettingsViewModel(
        ILogger logger, ICipherSuiteService cipherSuiteService, IUacIconService uacIconService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger)
    {
        MoveCipherSuiteUpCommand = new RelayCommand<UiWindowsApiCipherSuiteConfiguration?>(ExecuteMoveCipherSuiteUpCommand, CanExecuteMoveCipherSuiteUpCommand);
        MoveCipherSuiteDownCommand = new RelayCommand<UiWindowsApiCipherSuiteConfiguration?>(ExecuteMoveCipherSuiteDownCommand, CanExecuteMoveCipherSuiteDownCommand);
        DeleteCipherSuiteCommand = new RelayCommand<UiWindowsApiCipherSuiteConfiguration?>(ExecuteDeleteCipherSuiteCommand, CanExecuteDeleteCipherSuiteCommand);
        AddCipherSuiteCommand = new RelayCommand<UiWindowsDocumentationCipherSuiteConfiguration?>(ExecuteAddCipherSuiteCommand, CanExecuteAddCipherSuiteCommand);
        SaveCipherSuitesCommand = new AsyncRelayCommand(ExecuteSaveCipherSuitesCommandAsync, CanExecuteSaveCipherSuitesCommand);
        CancelCipherSuitesCommand = new RelayCommand(ExecuteCancelCipherSuitesCommand, CanExecuteCancelCipherSuitesCommand);
        ResetCipherSuitesCommand = new AsyncRelayCommand(ExecuteResetCipherSuitesCommandAsync, CanExecuteResetCipherSuitesCommand);
        CipherSuiteService = cipherSuiteService;
        this.uacIconService = uacIconService;
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;

        UpdateCanExecuteDefaultCommand();
    }

    public IRelayCommand MoveCipherSuiteUpCommand { get; }

    public IRelayCommand MoveCipherSuiteDownCommand { get; }

    public IRelayCommand DeleteCipherSuiteCommand { get; }

    public IRelayCommand AddCipherSuiteCommand { get; }

    public IAsyncRelayCommand SaveCipherSuitesCommand { get; }

    public IRelayCommand CancelCipherSuitesCommand { get; }

    public IAsyncRelayCommand ResetCipherSuitesCommand { get; }

    public BitmapSource UacIcon => uacIcon ??= uacIconService.GetUacShieldIcon();

    public bool FetchOnlineInfo
    {
        get => fetchOnlineInfo;
        set => _ = SetProperty(ref fetchOnlineInfo, value);
    }

    public ObservableCollection<UiWindowsApiCipherSuiteConfiguration>? ModifiedCipherSuiteConfigurations
    {
        get => modifiedCipherSuiteConfigurations;
        private set => _ = SetProperty(ref modifiedCipherSuiteConfigurations, value);
    }

    public ObservableCollection<UiWindowsDocumentationCipherSuiteConfiguration>? DefaultCipherSuiteConfigurations
    {
        get => defaultCipherSuiteConfigurations;
        private set => _ = SetProperty(ref defaultCipherSuiteConfigurations, value);
    }

    protected ICipherSuiteService CipherSuiteService { get; }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        IList<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations = CipherSuiteService.GetOperatingSystemDocumentationDefaultCipherSuiteList();
        IEnumerable<WindowsApiCipherSuiteConfiguration> windowsApiActiveCipherSuiteConfigurations = GetActiveCipherSuiteConfiguration();

        if (FetchOnlineInfo)
            await FetchOnlineCipherSuiteInfoAsync(windowsDocumentationCipherSuiteConfigurations, cancellationToken);

        ushort priority = ushort.MinValue;
        var uiWindowsApiCipherSuiteConfigurations = windowsApiActiveCipherSuiteConfigurations.Select(q => new UiWindowsApiCipherSuiteConfiguration(
            ++priority,
            q.CipherSuite,
            q.Protocols.Contains(SslProviderProtocolId.SSL2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.SSL3_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION),
            q.KeyType,
            q.Certificate,
            q.MaximumExchangeLength,
            q.MinimumExchangeLength,
            q.Exchange,
            q.HashLength,
            q.Hash,
            q.CipherBlockLength,
            q.CipherLength,
            q.Cipher,
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security)).ToList();

        priority = ushort.MinValue;

        var defaultUiWindowsDocumentationCipherSuiteConfigurations = windowsDocumentationCipherSuiteConfigurations.Select(q => new UiWindowsDocumentationCipherSuiteConfiguration(
            ++priority,
            q.CipherSuite,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault,
            q.Protocols.Contains(SslProviderProtocolId.SSL2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.SSL3_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION),
            q.Protocols.Contains(SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION),
            q.ExplicitApplicationRequestOnly,
            q.PreWindows10EllipticCurve,
            onlineCipherSuiteInfos.SingleOrDefault(r => q.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security)).ToList();

        DefaultCipherSuiteConfigurations = new(defaultUiWindowsDocumentationCipherSuiteConfigurations);
        activeCipherSuiteConfigurations = new(uiWindowsApiCipherSuiteConfigurations);
        ModifiedCipherSuiteConfigurations = new(activeCipherSuiteConfigurations);
    }

    protected abstract IEnumerable<WindowsApiCipherSuiteConfiguration> GetActiveCipherSuiteConfiguration();

    protected abstract void DoExecuteSaveCipherSuitesCommand();

    protected abstract void DoExecuteResetCipherSuitesCommand();

    protected virtual bool CanExecuteMoveCipherSuiteUpCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
        => uiWindowsApiCipherSuiteConfiguration is not null && ModifiedCipherSuiteConfigurations!.IndexOf(uiWindowsApiCipherSuiteConfiguration.Value) > 0;

    protected virtual bool CanExecuteMoveCipherSuiteDownCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
        => uiWindowsApiCipherSuiteConfiguration is not null && ModifiedCipherSuiteConfigurations!.IndexOf(uiWindowsApiCipherSuiteConfiguration.Value) < ModifiedCipherSuiteConfigurations.Count - 1;

    protected virtual bool CanExecuteDeleteCipherSuiteCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
        => uiWindowsApiCipherSuiteConfiguration is not null;

    protected virtual bool CanExecuteSaveCipherSuitesCommand()
        => !(activeCipherSuiteConfigurations?.SequenceEqual(ModifiedCipherSuiteConfigurations ?? []) ?? false);

    protected virtual bool CanExecuteCancelCipherSuitesCommand()
        => !(activeCipherSuiteConfigurations?.SequenceEqual(ModifiedCipherSuiteConfigurations ?? []) ?? false);

    protected virtual bool CanExecuteAddCipherSuiteCommand(UiWindowsDocumentationCipherSuiteConfiguration? uiWindowsDocumentationCipherSuiteConfiguration)
        => uiWindowsDocumentationCipherSuiteConfiguration is not null && ModifiedCipherSuiteConfigurations!.All(q => q.Id != uiWindowsDocumentationCipherSuiteConfiguration.Value.CipherSuite);

    protected virtual bool CanExecuteResetCipherSuitesCommand()
        => true;

    private async Task FetchOnlineCipherSuiteInfoAsync(IEnumerable<WindowsDocumentationCipherSuiteConfiguration> windowsDocumentationCipherSuiteConfigurations, CancellationToken cancellationToken)
    {
        CipherSuite?[] cipherSuites = await Task.WhenAll(windowsDocumentationCipherSuiteConfigurations.Select(q => cipherSuiteInfoApiService.GetCipherSuiteAsync(q.CipherSuite.ToString(), cancellationToken).AsTask()));

        onlineCipherSuiteInfos.Clear();
        onlineCipherSuiteInfos.AddRange(cipherSuites.Where(q => q is not null));
    }

    private void ExecuteMoveCipherSuiteUpCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
    {
        int index = ModifiedCipherSuiteConfigurations!.IndexOf(uiWindowsApiCipherSuiteConfiguration!.Value);

        ModifiedCipherSuiteConfigurations.Move(index, --index);
        NotifyCanExecuteChanged();
    }

    private void ExecuteMoveCipherSuiteDownCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
    {
        int index = ModifiedCipherSuiteConfigurations!.IndexOf(uiWindowsApiCipherSuiteConfiguration!.Value);

        ModifiedCipherSuiteConfigurations.Move(index, ++index);
        NotifyCanExecuteChanged();
    }

    private void ExecuteDeleteCipherSuiteCommand(UiWindowsApiCipherSuiteConfiguration? uiWindowsApiCipherSuiteConfiguration)
    {
        _ = ModifiedCipherSuiteConfigurations!.Remove(uiWindowsApiCipherSuiteConfiguration!.Value);
        NotifyCanExecuteChanged();
    }

    private void ExecuteAddCipherSuiteCommand(UiWindowsDocumentationCipherSuiteConfiguration? uiWindowsDocumentationCipherSuiteConfiguration)
    {
        WindowsApiCipherSuiteConfiguration windowsApiCipherSuiteConfiguration = CipherSuiteService.GetOperatingSystemDefaultCipherSuiteList().Single(q => q.CipherSuite == uiWindowsDocumentationCipherSuiteConfiguration!.Value.CipherSuite);

        ModifiedCipherSuiteConfigurations!.Add(new(
            (ushort)(ModifiedCipherSuiteConfigurations.Count + 1),
            windowsApiCipherSuiteConfiguration.CipherSuite,
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.SSL2_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.SSL3_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.Protocols.Contains(SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION),
            windowsApiCipherSuiteConfiguration.KeyType,
            windowsApiCipherSuiteConfiguration.Certificate,
            windowsApiCipherSuiteConfiguration.MaximumExchangeLength,
            windowsApiCipherSuiteConfiguration.MinimumExchangeLength,
            windowsApiCipherSuiteConfiguration.Exchange,
            windowsApiCipherSuiteConfiguration.HashLength,
            windowsApiCipherSuiteConfiguration.Hash,
            windowsApiCipherSuiteConfiguration.CipherBlockLength,
            windowsApiCipherSuiteConfiguration.CipherLength,
            windowsApiCipherSuiteConfiguration.Cipher,
            onlineCipherSuiteInfos.SingleOrDefault(r => windowsApiCipherSuiteConfiguration.CipherSuite.ToString().Equals(r!.Value.IanaName, StringComparison.OrdinalIgnoreCase), null)?.Security));
        NotifyCanExecuteChanged();
    }

    private async Task ExecuteSaveCipherSuitesCommandAsync()
    {
        DoExecuteSaveCipherSuitesCommand();
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
        NotifyCanExecuteChanged();
    }

    private void ExecuteCancelCipherSuitesCommand()
    {
        ModifiedCipherSuiteConfigurations = new(activeCipherSuiteConfigurations!);

        NotifyCanExecuteChanged();
    }

    private async Task ExecuteResetCipherSuitesCommandAsync()
    {
        DoExecuteResetCipherSuitesCommand();
        await DoExecuteDefaultCommandAsync(CancellationToken.None);
        NotifyCanExecuteChanged();
    }

    private void NotifyCanExecuteChanged()
    {
        MoveCipherSuiteUpCommand.NotifyCanExecuteChanged();
        MoveCipherSuiteDownCommand.NotifyCanExecuteChanged();
        SaveCipherSuitesCommand.NotifyCanExecuteChanged();
        CancelCipherSuitesCommand.NotifyCanExecuteChanged();
        AddCipherSuiteCommand.NotifyCanExecuteChanged();
        ResetCipherSuitesCommand.NotifyCanExecuteChanged();
    }
}