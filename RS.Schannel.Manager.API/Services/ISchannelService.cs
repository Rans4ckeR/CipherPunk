namespace RS.Schannel.Manager.API;

using Windows.Win32;

public interface ISchannelService
{
    string[] GetLocalCngConfigurationContextIdentifiers();

    List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList();

    List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList();

    List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

    void ResetCipherSuiteListToOperatingSystemDefault();

    void RemoveCipherSuite(string cipherSuite);

    void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite);

    void AddCipherSuite(string cipherSuite, bool top = true);

    void AddCipherSuite(SslProviderCipherSuiteId cipherSuite);

    void UpdateCipherSuiteOrder(string[] cipherSuites);

    void UpdateCipherSuiteOrder(SslProviderCipherSuiteId[] cipherSuites);

    List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList();

    List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList();

    List<string> GetOperatingSystemActiveEllipticCurveList();

    void ResetEllipticCurveListToOperatingSystemDefault();

    void UpdateEllipticCurveOrder(string[] ellipticCurves);

    void UpdateEllipticCurveOrder(BCRYPT_ECC_CURVE[] ellipticCurves);
}