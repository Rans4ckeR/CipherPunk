using System.Collections.Frozen;
using System.Runtime.Versioning;
using Windows.Win32;

namespace CipherPunk;

public interface ICipherSuiteService
{
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    IEnumerable<string> GetLocalCngConfigurationContextIdentifiers();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the default Cipher Suite configurations for the current OS from documentation.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the configured Ncrypt Cipher Suite configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemConfiguredCipherSuiteList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the OS's currently active Cipher Suite configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Gets the default Cipher Suite configurations for the current OS from Ncrypt.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();
#pragma warning restore CA1024 // Use properties where appropriate

    /// <summary>
    /// Resets the Ncrypt Cipher Suite configurations to the default for the current OS.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void ResetCipherSuiteListToOperatingSystemDefault();

    /// <summary>
    /// Removes a Cipher Suite using Ncrypt.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void RemoveCipherSuite(string cipherSuite);

    /// <summary>
    /// Removes a Cipher Suite using Ncrypt.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite);

    /// <summary>
    /// Adds a Cipher Suite using Ncrypt.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void AddCipherSuite(string cipherSuite, bool top = true);

    /// <summary>
    /// Adds a Cipher Suite using Ncrypt.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void AddCipherSuite(SslProviderCipherSuiteId cipherSuite);

    /// <summary>
    /// Sets the active Ncrypt Cipher Suite configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateCipherSuiteOrder(IEnumerable<string> cipherSuites);

    /// <summary>
    /// Sets the active Ncrypt Cipher Suite configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateCipherSuiteOrder(IEnumerable<SslProviderCipherSuiteId> cipherSuites);
}