namespace CipherPunk;

using System.Collections.ObjectModel;

public interface IWindowsCipherSuiteDocumentationService
{
    ReadOnlyDictionary<WindowsVersion, List<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations();

    List<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsVersion windowsVersion);
}