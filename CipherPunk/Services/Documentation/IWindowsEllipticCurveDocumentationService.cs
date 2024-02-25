namespace CipherPunk;

using System.Collections.Frozen;

internal interface IWindowsEllipticCurveDocumentationService
{
    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion windowsVersion);
}