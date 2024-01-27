namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CipherPunk.CipherSuiteInfoApi;

internal sealed class DefaultEllipticCurvesViewModel : BaseViewModel
{
    private readonly IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService;
    private readonly ITlsService tlsService;
    private ObservableCollection<WindowsVersion>? windowsVersions;
    private WindowsVersion? windowsVersion;
    private ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? defaultEllipticCurves;

    public DefaultEllipticCurvesViewModel(ILogger logger, IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService, IUacService uacService, ITlsService tlsService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.windowsEllipticCurveDocumentationService = windowsEllipticCurveDocumentationService;
        this.tlsService = tlsService;

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

    public ObservableCollection<UiWindowsDocumentationEllipticCurveConfiguration>? DefaultEllipticCurves
    {
        get => defaultEllipticCurves;
        private set => _ = SetProperty(ref defaultEllipticCurves, value);
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
        WindowsVersion ??= tlsService.GetWindowsVersion();

        return Task.CompletedTask;
    }

    private void OnWindowsVersionChanged()
    {
        try
        {
            FrozenSet<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfigurations = windowsEllipticCurveDocumentationService.GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion!.Value);
            IOrderedEnumerable<UiWindowsDocumentationEllipticCurveConfiguration> uiWindowsDocumentationCipherSuiteConfigurations = windowsDocumentationEllipticCurveConfigurations.Select(q => new UiWindowsDocumentationEllipticCurveConfiguration(
                q.Priority,
                q.Name,
                q.Identifier,
                q.Code,
                q.TlsSupportedGroup,
                q.AllowedByUseStrongCryptographyFlag,
                q.EnabledByDefault))
                .OrderBy(q => q.Priority);

            DefaultEllipticCurves = new(uiWindowsDocumentationCipherSuiteConfigurations);
        }
        catch (Exception ex)
        {
            Logger.ExceptionThrown(ex);
        }
    }
}