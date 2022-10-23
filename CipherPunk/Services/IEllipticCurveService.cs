namespace CipherPunk;

using System.Runtime.Versioning;

public interface IEllipticCurveService
{
    [SupportedOSPlatform("windows6.0.6000")]
    List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList();

    [SupportedOSPlatform("windows6.0.6000")]
    List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList();

    [SupportedOSPlatform("windows")]
    List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemActiveEllipticCurveList();

    [SupportedOSPlatform("windows6.0.6000")]
    void ResetEllipticCurveListToOperatingSystemDefault();

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateEllipticCurveOrder(string[] ellipticCurves);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateEllipticCurveOrder(BCRYPT_ECC_CURVE[] ellipticCurves);
}