namespace RS.Schannel.Manager.API;

public interface IWindowsCipherSuiteDocumentationService
{
    Dictionary<WindowsSchannelVersion, List<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations();

    List<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsSchannelVersion windowsSchannelVersion);
}