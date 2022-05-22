namespace RS.Schannel.Manager.CipherSuiteInfoApi;

public interface ICipherSuiteInfoApiService
{
    public const string HttpClientName = nameof(ICipherSuiteInfoApiService);

    Task<Ciphersuite> GetCipherSuite(string cipherSuiteName, CancellationToken cancellationToken);
}