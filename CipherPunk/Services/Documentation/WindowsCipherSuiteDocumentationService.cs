namespace CipherPunk;

using System.Collections.ObjectModel;

internal sealed class WindowsCipherSuiteDocumentationService : IWindowsCipherSuiteDocumentationService
{
    private ReadOnlyDictionary<WindowsVersion, List<WindowsDocumentationCipherSuiteConfiguration>>? windowsDocumentationCipherSuiteConfigurations;

    public ReadOnlyDictionary<WindowsVersion, List<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations()
        => windowsDocumentationCipherSuiteConfigurations ??= BuildWindowsDocumentationCipherSuiteConfigurations();

    public List<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsVersion windowsVersion)
        => GetWindowsDocumentationCipherSuiteConfigurations().First(q => q.Key <= windowsVersion).Value;

    private static ReadOnlyDictionary<WindowsVersion, List<WindowsDocumentationCipherSuiteConfiguration>> BuildWindowsDocumentationCipherSuiteConfigurations() =>
        new List<(WindowsVersion Version, List<WindowsDocumentationCipherSuiteConfiguration> Configurations)>
        {
            Windows11V22H2CipherSuiteDocumentationService.GetConfiguration(),
            Windows11V21H2CipherSuiteDocumentationService.GetConfiguration(),
            WindowsServer2022CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V22H2CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V1903CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V1709CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V1703CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V1607CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V1511CipherSuiteDocumentationService.GetConfiguration(),
            Windows10V1507CipherSuiteDocumentationService.GetConfiguration(),
            Windows81CipherSuiteDocumentationService.GetConfiguration(),
            Windows8CipherSuiteDocumentationService.GetConfiguration(),
            Windows7CipherSuiteDocumentationService.GetConfiguration(),
            WindowsVistaCipherSuiteDocumentationService.GetConfiguration()
        }.ToDictionary(q => q.Version, q => q.Configurations).AsReadOnly();
}