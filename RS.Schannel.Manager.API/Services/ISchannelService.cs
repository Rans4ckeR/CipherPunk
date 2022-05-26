namespace RS.Schannel.Manager.API;

public interface ISchannelService
{
    string[] GetLocalCngConfigurationContextIdentifiers();

    List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

    Task<List<WindowsApiCipherSuiteConfiguration>> GetOperatingSystemActiveCipherSuiteListAsync(CancellationToken cancellationToken = default);

    void ResetList();

    void RemoveCipher(string cipher);

    void AddCipher(string cipher, bool top = true);
}