namespace CipherPunk.CipherSuiteInfoApi;

public interface ICipherSuiteInfoApiService
{
    public const string HttpClientName = nameof(ICipherSuiteInfoApiService);

    Task<CipherSuite?> GetCipherSuite(string cipherSuiteName, CancellationToken cancellationToken);

    Task<CipherSuite[]> GetAllCipherSuites(CancellationToken cancellationToken);
}