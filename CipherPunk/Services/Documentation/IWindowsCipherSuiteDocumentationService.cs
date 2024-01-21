namespace CipherPunk;

using System.Collections.Frozen;

public interface IWindowsCipherSuiteDocumentationService
{
    FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations();

    FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsVersion windowsVersion);
}