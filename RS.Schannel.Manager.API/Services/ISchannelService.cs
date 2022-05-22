namespace RS.Schannel.Manager.API;

public interface ISchannelService
{
    string[] GetLocalCngConfigurationContextIdentifiers();

    List<WindowsCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList();

    Task<List<CipherSuiteConfiguration>> GetOperatingSystemActiveCipherSuiteListAsync(bool includeOnlineInfo = true, CancellationToken cancellationToken = default);

    void ResetList();

    void RemoveCipher(string cipher);

    void AddCipher(string cipher, bool top = true);
}