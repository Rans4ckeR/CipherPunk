namespace CipherPunk;

using System.Collections.Frozen;

public interface IWindowsEllipticCurveDocumentationService
{
    FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>> GetWindowsDocumentationEllipticCurveConfigurations();

    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion windowsVersion);
}