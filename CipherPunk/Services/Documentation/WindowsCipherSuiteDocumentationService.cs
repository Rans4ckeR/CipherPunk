namespace CipherPunk;

using System.Collections.Frozen;

internal sealed class WindowsCipherSuiteDocumentationService : IWindowsCipherSuiteDocumentationService
{
    private FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>>? windowsDocumentationCipherSuiteConfigurations;

    public FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> GetWindowsDocumentationCipherSuiteConfigurations()
        => windowsDocumentationCipherSuiteConfigurations ??= BuildWindowsDocumentationCipherSuiteConfigurations();

    public FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetWindowsDocumentationCipherSuiteConfigurations(WindowsVersion windowsVersion)
        => GetWindowsDocumentationCipherSuiteConfigurations().Where(q => q.Key <= windowsVersion).MaxBy(q => q.Key).Value;

    private static FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>> BuildWindowsDocumentationCipherSuiteConfigurations()
        => FrozenDictionary.ToFrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationCipherSuiteConfiguration>>(
        [
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
        ]);
}