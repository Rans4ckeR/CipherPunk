namespace CipherPunk;

using System.Collections.Frozen;
using System.Runtime.Versioning;

public interface IEllipticCurveService
{
    /// <summary>
    /// Gets the default Elliptic Curve configurations for the current OS.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList();

    /// <summary>
    /// Gets the available Elliptic Curve configurations for the current OS.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList();

    /// <summary>
    /// Gets the OS's currently active Elliptic Curve configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsApiEllipticCurveConfiguration> GetOperatingSystemActiveEllipticCurveList();

    /// <summary>
    /// Gets the configured Ncrypt Elliptic Curve configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsApiEllipticCurveConfiguration> GetOperatingSystemConfiguredEllipticCurveList();

    /// <summary>
    /// Resets the Ncrypt Elliptic Curve configurations to the default for the current OS.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void ResetEllipticCurveListToOperatingSystemDefault();

    /// <summary>
    /// Sets the active Ncrypt Elliptic Curve configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateEllipticCurveOrder(IEnumerable<string> ellipticCurves);

    /// <summary>
    /// Sets the active Ncrypt Elliptic Curve configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateEllipticCurveOrder(IEnumerable<BCRYPT_ECC_CURVE> ellipticCurves);
}