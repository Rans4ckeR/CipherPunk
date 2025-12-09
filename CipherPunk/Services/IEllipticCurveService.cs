using System.Collections.Frozen;
using System.Runtime.Versioning;

namespace CipherPunk;

public interface IEllipticCurveService
{
    /// <summary>
    /// Gets the default Elliptic Curve configurations for the current OS.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the available Elliptic Curve configurations for the current OS.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the OS's currently active Elliptic Curve configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<WindowsApiEllipticCurveConfiguration> GetOperatingSystemActiveEllipticCurveList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the configured Ncrypt Elliptic Curve configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<WindowsApiEllipticCurveConfiguration> GetOperatingSystemConfiguredEllipticCurveList();
#pragma warning restore CA1024 // Use properties where appropriate

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