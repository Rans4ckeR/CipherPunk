namespace CipherPunk;

using System.Collections.ObjectModel;

public interface IWindowsCipherSuiteDocumentationService
{
    ReadOnlyDictionary<WindowsSchannelVersion, List<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations();

    List<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsSchannelVersion windowsSchannelVersion);
}