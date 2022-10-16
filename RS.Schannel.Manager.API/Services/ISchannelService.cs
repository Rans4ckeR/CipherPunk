namespace RS.Schannel.Manager.API;

using System.Runtime.Versioning;
using Windows.Win32;

public interface ISchannelService
{
    [SupportedOSPlatform("windows6.0.6000")]
    string[] GetLocalCngConfigurationContextIdentifiers();

    [SupportedOSPlatform("windows6.0.6000")]
    List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList();

    [SupportedOSPlatform("windows6.0.6000")]
    List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList();

    [SupportedOSPlatform("windows6.0.6000")]
    List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

    [SupportedOSPlatform("windows6.0.6000")]
    void ResetCipherSuiteListToOperatingSystemDefault();

    [SupportedOSPlatform("windows6.0.6000")]
    void RemoveCipherSuite(string cipherSuite);

    [SupportedOSPlatform("windows6.0.6000")]
    void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite);

    [SupportedOSPlatform("windows6.0.6000")]
    void AddCipherSuite(string cipherSuite, bool top = true);

    [SupportedOSPlatform("windows6.0.6000")]
    void AddCipherSuite(SslProviderCipherSuiteId cipherSuite);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateCipherSuiteOrder(string[] cipherSuites);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateCipherSuiteOrder(SslProviderCipherSuiteId[] cipherSuites);
}