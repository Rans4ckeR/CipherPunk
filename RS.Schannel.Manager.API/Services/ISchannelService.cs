namespace RS.Schannel.Manager.API;

using Windows.Win32;

public interface ISchannelService
{
    public string[] GetLocalCngConfigurationContextIdentifiers();

    public List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList();

    public List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList();

    public List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

    public void ResetCipherSuiteListToOperatingSystemDefault();

    public void RemoveCipherSuite(string cipherSuite);

    public void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite);

    public void AddCipherSuite(string cipherSuite, bool top = true);

    public void AddCipherSuite(SslProviderCipherSuiteId cipherSuite);

    public void UpdateCipherSuiteOrder(string[] cipherSuites);

    public void UpdateCipherSuiteOrder(SslProviderCipherSuiteId[] cipherSuites);

    public List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList();

    public List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList();

    public List<string> GetOperatingSystemActiveEllipticCurveList();

    public void ResetEllipticCurveListToOperatingSystemDefault();

    public void UpdateEllipticCurveOrder(string[] ellipticCurves);

    public void UpdateEllipticCurveOrder(BCRYPT_ECC_CURVE[] ellipticCurves);
}