using System.Collections.Frozen;
using System.Collections.ObjectModel;
using CipherPunk.CipherSuiteInfoApi;

namespace CipherPunk.UI;

internal sealed class EllipticCurvesViewModel : BaseViewModel
{
    private readonly IEllipticCurveService ellipticCurveService;

    public EllipticCurvesViewModel(ILogger logger, IEllipticCurveService ellipticCurveService, IUacService uacService, ICipherSuiteInfoApiService cipherSuiteInfoApiService)
        : base(logger, uacService, cipherSuiteInfoApiService)
    {
        this.ellipticCurveService = ellipticCurveService;

        UpdateCanExecuteDefaultCommand();
    }

    public ObservableCollection<UiWindowsApiEllipticCurveConfiguration>? ActiveEllipticCurveConfigurations
    {
        get;
        private set => _ = SetProperty(ref field, value);
    }

    protected override Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        FrozenSet<WindowsApiEllipticCurveConfiguration> windowsApiActiveEllipticCurveConfigurations = ellipticCurveService.GetOperatingSystemActiveEllipticCurveList();
        IOrderedEnumerable<UiWindowsApiEllipticCurveConfiguration> uiWindowsApiEllipticCurveConfigurations = windowsApiActiveEllipticCurveConfigurations.Select(q => new UiWindowsApiEllipticCurveConfiguration(
            q.Priority,
            q.pszOid,
            q.pwszName,
            q.dwBitLength,
            string.Join(',', q.CngAlgorithms)))
            .OrderBy(q => q.Priority);

        ActiveEllipticCurveConfigurations = [.. uiWindowsApiEllipticCurveConfigurations];

        return Task.CompletedTask;
    }
}