namespace CipherPunk;

internal interface IWindowsEllipticCurveDocumentationService
{
    Dictionary<WindowsVersion, List<WindowsDocumentationEllipticCurveConfiguration>> GetWindowsDocumentationEllipticCurveConfigurations();

    List<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion windowsVersion);
}