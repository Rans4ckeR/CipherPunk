namespace CipherPunk.UI;

using System.Collections.ObjectModel;

internal abstract class BaseEllipticCurvesSettingsViewModel(ILogger logger, IEllipticCurveService ellipticCurveService, IUacIconService uacIconService)
    : BaseSettingsViewModel<WindowsApiEllipticCurveConfiguration, UiWindowsApiEllipticCurveConfiguration, UiWindowsApiEllipticCurveConfiguration, UiWindowsDocumentationEllipticCurveConfiguration>(logger, uacIconService)
{
    private ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? availableSettingConfigurations;

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? AvailableSettingConfigurations
    {
        get => availableSettingConfigurations;
        private set => _ = SetProperty(ref availableSettingConfigurations, value);
    }

    protected IEllipticCurveService EllipticCurveService { get; } = ellipticCurveService;

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        IEnumerable<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = GetActiveSettingConfiguration();
        List<WindowsApiEllipticCurveConfiguration> windowsApiAvailableEllipticCurveConfigurations = EllipticCurveService.GetOperatingSystemAvailableEllipticCurveList();
        List<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfiguration = EllipticCurveService.GetOperatingSystemDefaultEllipticCurveList();

        ushort priority = ushort.MinValue;
        var uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            ++priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms))).ToList();

        var uiWindowsApiAvailableEllipticCurveConfigurations = windowsApiAvailableEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            0,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms))).ToList();

        priority = ushort.MinValue;

        var uiWindowsDocumentationEllipticCurveConfiguration = windowsDocumentationEllipticCurveConfiguration.Select(q => new UiWindowsDocumentationEllipticCurveConfiguration(
            ++priority,
            q.Name,
            q.Identifier,
            q.Code,
            q.TlsSupportedGroup,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault)).ToList();

        DefaultSettingConfigurations = new(uiWindowsDocumentationEllipticCurveConfiguration);
        AvailableSettingConfigurations = new(uiWindowsApiAvailableEllipticCurveConfigurations);
        ActiveSettingConfigurations = new(uiWindowsApiEllipticCurveConfigurations);
        ModifiedSettingConfigurations = new(ActiveSettingConfigurations);

        return Task.CompletedTask;
    }

    protected override bool CompareSetting(UiWindowsApiEllipticCurveConfiguration userInterfaceSettingConfiguration, UiWindowsApiEllipticCurveConfiguration availableSettingConfiguration)
        => userInterfaceSettingConfiguration.Id == availableSettingConfiguration.Id;

    protected override UiWindowsApiEllipticCurveConfiguration ConvertSettingCommand(UiWindowsApiEllipticCurveConfiguration availableSettingConfiguration)
    {
        WindowsApiEllipticCurveConfiguration windowsApiEllipticCurveConfiguration = EllipticCurveService.GetOperatingSystemAvailableEllipticCurveList().Single(q => q.pwszName == availableSettingConfiguration.Name);

        return new(
            (ushort)(ModifiedSettingConfigurations!.Count + 1),
            windowsApiEllipticCurveConfiguration.pszOid,
            windowsApiEllipticCurveConfiguration.pwszName,
            windowsApiEllipticCurveConfiguration.dwBitLength,
            string.Join(',', windowsApiEllipticCurveConfiguration.CngAlgorithms));
    }
}