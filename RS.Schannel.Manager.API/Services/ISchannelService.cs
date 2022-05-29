namespace RS.Schannel.Manager.API;

public interface ISchannelService
{
    string[] GetLocalCngConfigurationContextIdentifiers();

    List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

    List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList();

    void ResetCipherSuiteListToOperatingSystemDefault();

    void UpdateCipherSuiteOrder(string[] cipherSuites);

    void RemoveCipherSuite(string cipherSuite);

    void AddCipherSuite(string cipherSuite, bool top = true);

    List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList();

    List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList();

    List<string> GetOperatingSystemActiveEllipticCurveList();

    void ResetEllipticCurveListToOperatingSystemDefault();

    void UpdateEllipticCurveOrder(string[] ellipticCurves);
}