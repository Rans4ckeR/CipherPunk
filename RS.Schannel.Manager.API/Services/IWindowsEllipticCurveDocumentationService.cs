namespace RS.Schannel.Manager.API;

internal interface IWindowsEllipticCurveDocumentationService
{
    Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>> GetWindowsDocumentationEllipticCurveConfigurations();

    List<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsSchannelVersion windowsSchannelVersion);
}