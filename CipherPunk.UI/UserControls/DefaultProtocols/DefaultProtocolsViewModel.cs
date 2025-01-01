using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class DefaultProtocolsViewModel : BaseViewModel
{
    private readonly IWindowsDocumentationService windowsDocumentationService;
    private readonly IWindowsVersionService windowsVersionService;

    public DefaultProtocolsViewModel(ILogger logger, IWindowsDocumentationService windowsDocumentationService, IUacService uacService, IWindowsVersionService windowsVersionService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.windowsDocumentationService = windowsDocumentationService;
        this.windowsVersionService = windowsVersionService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<WindowsVersion>? WindowsVersions
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    public WindowsVersion? WindowsVersion
    {
        get;
        set => _ = SetProperty(ref field, value);
    }

    public ObservableCollection<SchannelProtocolSettings>? DefaultProtocols
    {
        get;
        private set => _ = SetProperty(ref field, value);
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
        WindowsVersions ??= [.. Enum.GetValues<WindowsVersion>().OrderByDescending(static q => (int)q)];
        WindowsVersion ??= windowsVersionService.WindowsVersion;

        return Task.CompletedTask;
    }

    private void OnWindowsVersionChanged()
    {
        try
        {
            FrozenSet<SchannelProtocolSettings> windowsDocumentationProtocolConfigurations = windowsDocumentationService.GetProtocolConfigurations(WindowsVersion!.Value);

            DefaultProtocols = [.. windowsDocumentationProtocolConfigurations];
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
    }
}