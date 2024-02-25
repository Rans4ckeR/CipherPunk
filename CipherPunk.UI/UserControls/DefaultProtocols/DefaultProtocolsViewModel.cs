namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;

internal sealed class DefaultProtocolsViewModel : BaseViewModel
{
    private readonly IWindowsDocumentationService windowsDocumentationService;
    private readonly IWindowsVersionService windowsVersionService;
    private ObservableCollection<WindowsVersion>? windowsVersions;
    private WindowsVersion? windowsVersion;
    private ObservableCollection<SchannelProtocolSettings>? defaultProtocols;

    public DefaultProtocolsViewModel(ILogger logger, IWindowsDocumentationService windowsDocumentationService, IUacService uacService, IWindowsVersionService windowsVersionService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.windowsDocumentationService = windowsDocumentationService;
        this.windowsVersionService = windowsVersionService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<WindowsVersion>? WindowsVersions
    {
        get => windowsVersions;
        private set => _ = SetProperty(ref windowsVersions, value);
    }

    public WindowsVersion? WindowsVersion
    {
        get => windowsVersion;
        set => _ = SetProperty(ref windowsVersion, value);
    }

    public ObservableCollection<SchannelProtocolSettings>? DefaultProtocols
    {
        get => defaultProtocols;
        private set => _ = SetProperty(ref defaultProtocols, value);
    }

    protected override void BaseViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        base.BaseViewModelPropertyChanged(sender, e);

        switch (e.PropertyName)
        {
            case nameof(WindowsVersion):
                OnWindowsVersionChanged();
                break;
        }
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        WindowsVersions ??= new(Enum.GetValues<WindowsVersion>().OrderByDescending(q => (int)q));
        WindowsVersion ??= windowsVersionService.WindowsVersion;

        return Task.CompletedTask;
    }

    private void OnWindowsVersionChanged()
    {
        try
        {
            FrozenSet<SchannelProtocolSettings> windowsDocumentationProtocolConfigurations = windowsDocumentationService.GetProtocolConfigurations(WindowsVersion!.Value);

            DefaultProtocols = new(windowsDocumentationProtocolConfigurations);
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
    }
}