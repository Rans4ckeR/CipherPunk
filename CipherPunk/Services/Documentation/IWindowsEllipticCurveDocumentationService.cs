using System.Collections.Frozen;

namespace CipherPunk;

internal interface IWindowsEllipticCurveDocumentationService
{
    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion windowsVersion);
}