using System.Collections.Frozen;
using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal abstract class BaseEllipticCurvesSettingsViewModel(ILogger logger, IEllipticCurveService ellipticCurveService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    : BaseSettingsViewModel<WindowsApiEllipticCurveConfiguration, UiWindowsApiEllipticCurveConfiguration, UiWindowsApiEllipticCurveConfiguration, UiWindowsDocumentationEllipticCurveConfiguration>(logger, uacService, cipherSuiteInfoApiService)
{
    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? AvailableSettingConfigurations
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected IEllipticCurveService EllipticCurveService { get; } = ellipticCurveService;

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        IEnumerable<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = GetActiveSettingConfiguration();
        IReadOnlyCollection<WindowsApiEllipticCurveConfiguration> windowsApiAvailableEllipticCurveConfigurations = EllipticCurveService.GetOperatingSystemAvailableEllipticCurveList();
        FrozenSet<WindowsDocumentationEllipticCurveConfiguration> windowsDocumentationEllipticCurveConfiguration = EllipticCurveService.GetOperatingSystemDefaultEllipticCurveList();
        IEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(static q => new UiWindowsApiEllipticCurveConfiguration(
            q.Priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)));
        IEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiAvailableEllipticCurveConfigurations = windowsApiAvailableEllipticCurveConfigurations.Select(static q => new UiWindowsApiEllipticCurveConfiguration(
            ushort.MinValue,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)))
            .OrderBy(static q => q.Id)
            .ThenBy(static q => q.Name);
        IOrderedEnumerable<UiWindowsDocumentationEllipticCurveConfiguration> uiWindowsDocumentationEllipticCurveConfiguration = windowsDocumentationEllipticCurveConfiguration.Select(static q => new UiWindowsDocumentationEllipticCurveConfiguration(
            q.Priority,
            q.Name,
            q.Identifier,
            q.Code,
            q.TlsSupportedGroup,
            q.AllowedByUseStrongCryptographyFlag,
            q.EnabledByDefault))
            .OrderBy(static q => q.Priority);

        DefaultSettingConfigurations = [.. uiWindowsDocumentationEllipticCurveConfiguration];
        AvailableSettingConfigurations = [.. uiWindowsApiAvailableEllipticCurveConfigurations];
        ActiveSettingConfigurations = [.. uiWindowsApiEllipticCurveConfigurations];
        ModifiedSettingConfigurations = [.. ActiveSettingConfigurations];

        return Task.CompletedTask;
    }

    protected override bool CompareSetting(UiWindowsApiEllipticCurveConfiguration userInterfaceSettingConfiguration, UiWindowsApiEllipticCurveConfiguration availableSettingConfiguration)
        => userInterfaceSettingConfiguration.Name.Equals(availableSettingConfiguration.Name, StringComparison.OrdinalIgnoreCase);

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