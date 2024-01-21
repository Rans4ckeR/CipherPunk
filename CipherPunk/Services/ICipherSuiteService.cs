namespace CipherPunk;

using System.Collections.Frozen;
using System.Runtime.Versioning;
using Windows.Win32;

public interface ICipherSuiteService
{
    [SupportedOSPlatform("windows6.0.6000")]
    IEnumerable<string> GetLocalCngConfigurationContextIdentifiers();

    /// <summary>
    /// Gets the default Cipher Suite configurations for the current OS from documentation.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList();

    /// <summary>
    /// Gets the configured Ncrypt Cipher Suite configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemConfiguredCipherSuiteList();

    /// <summary>
    /// Gets the OS's currently active Cipher Suite configurations.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList();

    /// <summary>
    /// Gets the default Cipher Suite configurations for the current OS from Ncrypt.
    /// </summary>
    [SupportedOSPlatform("windows6.0.6000")]
    FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

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