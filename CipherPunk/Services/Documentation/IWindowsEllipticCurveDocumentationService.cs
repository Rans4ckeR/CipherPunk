using System.Collections.Frozen;

namespace CipherPunk;

public interface IWindowsEllipticCurveDocumentationService
{
    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion windowsVersion);
}