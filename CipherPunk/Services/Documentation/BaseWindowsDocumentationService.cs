using System.Collections.Frozen;

namespace CipherPunk;

internal abstract class BaseWindowsDocumentationService(WindowsVersion windowsVersion, IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService)
{
    private readonly IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService = windowsEllipticCurveDocumentationService;

    private KeyValuePair<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>>? windowsDocumentationCipherSuiteConfigurations;

    public WindowsVersion WindowsVersion { get; } = windowsVersion;

    public KeyValuePair<WindowsVersion, FrozenSet<SchannelProtocolSettings>> GetProtocolConfiguration()
        => new(WindowsVersion, GetProtocolDefaultConfiguration().ToFrozenSet());

    public KeyValuePair<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> GetCipherSuiteConfiguration()
        => windowsDocumentationCipherSuiteConfigurations ??= new(WindowsVersion, FrozenSet.ToFrozenSet([.. GetCipherSuiteDefaultEnabledConfiguration(), .. GetCipherSuiteDefaultDisabledConfiguration(), .. GetCipherSuitePreSharedKeyConfiguration()]));

    public KeyValuePair<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>> GetEllipticCurveConfiguration()
        => new(WindowsVersion, windowsEllipticCurveDocumentationService.GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion));

    protected abstract IEnumerable<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuiteDefaultEnabledConfiguration();

    protected abstract IEnumerable<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuiteDefaultDisabledConfiguration();

    protected virtual IEnumerable<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuitePreSharedKeyConfiguration() => [];

    private IEnumerable<SchannelProtocolSettings> GetProtocolDefaultConfiguration() =>
        Enum.GetValues<SchannelProtocol>().Select<SchannelProtocol, SchannelProtocolSettings>(schannelProtocol => schannelProtocol switch
        {
            SchannelProtocol.UNIHELLO => new(schannelProtocol, SchannelProtocolStatus.NotSupported, SchannelProtocolStatus.NotSupported),
            SchannelProtocol.PCT1_0 => new(schannelProtocol, SchannelProtocolStatus.NotSupported, SchannelProtocolStatus.NotSupported),
            SchannelProtocol.SSL2_0 => new(
                schannelProtocol,
                WindowsVersion < WindowsVersion.Windows10V1607OrServer2016 ? SchannelProtocolStatus.Disabled : SchannelProtocolStatus.NotSupported,
                WindowsVersion < WindowsVersion.Windows8OrServer2012 ? SchannelProtocolStatus.Enabled : WindowsVersion < WindowsVersion.Windows10V1607OrServer2016 ? SchannelProtocolStatus.Disabled : SchannelProtocolStatus.NotSupported),
            SchannelProtocol.SSL3_0 => new(
                schannelProtocol,
                WindowsVersion < WindowsVersion.Windows10V1607OrServer2016 ? SchannelProtocolStatus.Enabled : SchannelProtocolStatus.Disabled,
                WindowsVersion < WindowsVersion.Windows10V1607OrServer2016 ? SchannelProtocolStatus.Enabled : SchannelProtocolStatus.Disabled),
            SchannelProtocol.DTLS1_0 => new(
                schannelProtocol,
                WindowsVersion < WindowsVersion.Windows7OrServer2008R2 ? SchannelProtocolStatus.NotSupported : SchannelProtocolStatus.Enabled,
                WindowsVersion < WindowsVersion.Windows7OrServer2008R2 ? SchannelProtocolStatus.NotSupported : SchannelProtocolStatus.Enabled),
            SchannelProtocol.DTLS1_2 => new(
                schannelProtocol,
                WindowsVersion < WindowsVersion.Windows10V1607OrServer2016 ? SchannelProtocolStatus.NotSupported : SchannelProtocolStatus.Enabled,
                WindowsVersion < WindowsVersion.Windows10V1607OrServer2016 ? SchannelProtocolStatus.NotSupported : SchannelProtocolStatus.Enabled),
            SchannelProtocol.DTLS1_3 => new(schannelProtocol, SchannelProtocolStatus.NotSupported, SchannelProtocolStatus.NotSupported),
            SchannelProtocol.TLS1_0 => new(schannelProtocol, SchannelProtocolStatus.Enabled, SchannelProtocolStatus.Enabled),
            SchannelProtocol.TLS1_1 or SchannelProtocol.TLS1_2 => new(
                schannelProtocol,
                WindowsVersion < WindowsVersion.WindowsServer2008SP2 ? SchannelProtocolStatus.NotSupported : WindowsVersion < WindowsVersion.Windows8OrServer2012 ? SchannelProtocolStatus.Disabled : SchannelProtocolStatus.Enabled,
                WindowsVersion < WindowsVersion.WindowsServer2008SP2 ? SchannelProtocolStatus.NotSupported : WindowsVersion < WindowsVersion.Windows8OrServer2012 ? SchannelProtocolStatus.Disabled : SchannelProtocolStatus.Enabled),
            SchannelProtocol.TLS1_3 => new(
                schannelProtocol,
                WindowsVersion < WindowsVersion.WindowsServer2022 ? SchannelProtocolStatus.NotSupported : SchannelProtocolStatus.Enabled,
                WindowsVersion < WindowsVersion.WindowsServer2022 ? SchannelProtocolStatus.NotSupported : SchannelProtocolStatus.Enabled),
            _ => throw new ArgumentOutOfRangeException(nameof(schannelProtocol), schannelProtocol, null)
        });
}