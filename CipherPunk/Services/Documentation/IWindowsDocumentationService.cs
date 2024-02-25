namespace CipherPunk;

using System.Collections.Frozen;

public interface IWindowsDocumentationService
{
    FrozenDictionary<WindowsVersion, FrozenSet<SchannelProtocolSettings>> GetProtocolConfigurations();

    FrozenSet<SchannelProtocolSettings> GetProtocolConfigurations(WindowsVersion windowsVersion);

    FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> GetCipherSuiteConfigurations();

    FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetCipherSuiteConfigurations(WindowsVersion windowsVersion);

    FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>> GetEllipticCurveConfigurations();

    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetEllipticCurveConfigurations(WindowsVersion windowsVersion);
}