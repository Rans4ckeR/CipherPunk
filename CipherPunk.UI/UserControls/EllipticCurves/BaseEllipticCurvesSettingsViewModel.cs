namespace CipherPunk.UI;

using System.Collections.Frozen;
using System.Collections.ObjectModel;

internal abstract class BaseEllipticCurvesSettingsViewModel(ILogger logger, IEllipticCurveService ellipticCurveService, IUacService uacService)
    : BaseSettingsViewModel<WindowsApiEllipticCurveConfiguration, UiWindowsApiEllipticCurveConfiguration, UiWindowsApiEllipticCurveConfiguration, UiWindowsDocumentationEllipticCurveConfiguration>(logger, uacService)
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
        FrozenSet<WindowsApiEllipticCurveConfiguration> windowsApiAvailableEllipticCurveConfigurations = EllipticCurveService.GetOperatingSystemAvailableEllipticCurveList();
        FrozenSet<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfiguration = EllipticCurveService.GetOperatingSystemDefaultEllipticCurveList();
        IEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            q.Priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)));
        IEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiAvailableEllipticCurveConfigurations = windowsApiAvailableEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            ushort.MinValue,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)))
            .OrderBy(q => q.Id)
            .ThenBy(q => q.Name);
        IOrderedEnumerable<UiWindowsDocumentationEllipticCurveConfiguration> uiWindowsDocumentationEllipticCurveConfiguration = windowsDocumentationEllipticCurveConfiguration.Select(q => new UiWindowsDocumentationEllipticCurveConfiguration(
            q.Priority,
            q.Name,
            q.Identifier,
            q.Code,
            q.TlsSupportedGroup,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault))
            .OrderBy(q => q.Priority);

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