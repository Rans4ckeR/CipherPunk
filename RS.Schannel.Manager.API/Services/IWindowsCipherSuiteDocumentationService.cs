namespace RS.Schannel.Manager.API;

public interface IWindowsCipherSuiteDocumentationService
{
    Dictionary<WindowsCipherSuiteListVersion, List<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations();
}