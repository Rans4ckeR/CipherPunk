namespace RS.Schannel.Manager.UI;

using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;
using Microsoft.Extensions.Logging;
using RS.Schannel.Manager.API;

internal sealed class CipherSuitesViewModel : BaseViewModel
{
    private readonly ISchannelService schannelService;
    private readonly IUacIconService uacIconService;
    private ObservableCollection<CipherSuiteConfiguration>? activeCipherSuiteConfigurations;
    private ObservableCollection<WindowsCipherSuiteConfiguration>? osDefaultCipherSuiteConfigurations;
    private BitmapSource? uacIcon;

    public CipherSuitesViewModel(ILogger logger, ISchannelService schannelService, IUacIconService uacIconService)
        : base(logger)
    {
        this.schannelService = schannelService;
        this.uacIconService = uacIconService;

        UpdateCanExecuteDefaultCommand();
    }

    public BitmapSource UacIcon
    {
        get => uacIcon ??= uacIconService.GetUacShieldIcon();
    }

    public ObservableCollection<CipherSuiteConfiguration>? ActiveCipherSuiteConfigurations
    {
        get => activeCipherSuiteConfigurations;
        private set => _ = SetProperty(ref activeCipherSuiteConfigurations, value);
    }

    public ObservableCollection<WindowsCipherSuiteConfiguration>? OsDefaultCipherSuiteConfigurations
    {
        get => osDefaultCipherSuiteConfigurations;
        private set => _ = SetProperty(ref osDefaultCipherSuiteConfigurations, value);
    }

    protected override async Task DoExecuteDefaultCommandAsync(CancellationToken cancellationToken)
    {
        ActiveCipherSuiteConfigurations = new ObservableCollection<CipherSuiteConfiguration>(await schannelService.GetOperatingSystemActiveCipherSuiteListAsync(true, cancellationToken));
        OsDefaultCipherSuiteConfigurations = new ObservableCollection<WindowsCipherSuiteConfiguration>(schannelService.GetOperatingSystemDefaultCipherSuiteList());
    }
}