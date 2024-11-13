using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class DefaultEllipticCurvesViewModel : BaseViewModel
{
    private readonly IWindowsDocumentationService windowsDocumentationService;
    private readonly IWindowsVersionService windowsVersionService;

    public DefaultEllipticCurvesViewModel(ILogger logger, IWindowsDocumentationService windowsDocumentationService, IUacService uacService, IWindowsVersionService windowsVersionService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
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

    public ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? DefaultEllipticCurves
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
        WindowsVersions ??= [.. Enum.GetValues<WindowsVersion>().OrderByDescending(q => (int)q)];
        WindowsVersion ??= windowsVersionService.WindowsVersion;

        return Task.CompletedTask;
    }

    private void OnWindowsVersionChanged()
    {
        try
        {
            FrozenSet<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfigurations = windowsDocumentationService.GetEllipticCurveConfigurations(WindowsVersion!.Value);
            IOrderedEnumerable<UiWindowsDocumentationEllipticCurveConfiguration> uiWindowsDocumentationCipherSuiteConfigurations = windowsDocumentationEllipticCurveConfigurations.Select(q => new UiWindowsDocumentationEllipticCurveConfiguration(
                q.Priority,
                q.Name,
                q.Identifier,
                q.Code,
                q.TlsSupportedGroup,
                q.AllowedByUseStrongCryptographyFlag,
                q.EnabledByDefault))
                .OrderBy(q => q.Priority);

            DefaultEllipticCurves = [.. uiWindowsDocumentationCipherSuiteConfigurations];
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
    }
}