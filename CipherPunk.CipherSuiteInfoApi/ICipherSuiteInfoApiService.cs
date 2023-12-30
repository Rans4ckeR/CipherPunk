namespace CipherPunk.CipherSuiteInfoApi;

public interface ICipherSuiteInfoApiService
{
    internal const string HttpClientName = nameof(ICipherSuiteInfoApiService);

    /// <summary>
    /// Retrieve online information for <paramref name="cipherSuiteName"/> as a <see cref="CipherSuite"/> instance.
    /// </summary>
    /// <param name="cipherSuiteName">The name of the cipher suite to retrieve the online information for.</param>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to cancel the operation.</param>
    /// <returns>The <see cref="ValueTask"/> object representing the asynchronous operation.</returns>
    ValueTask<CipherSuite?> GetCipherSuiteAsync(string cipherSuiteName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieve online information for all known cipher suites as an array of <see cref="CipherSuite"/>.
    /// </summary>
    /// <param name="cancellationToken">The <see cref="CancellationToken"/> to cancel the operation.</param>
    /// <returns>The <see cref="ValueTask"/> object representing the asynchronous operation.</returns>
    ValueTask<CipherSuite[]> GetAllCipherSuitesAsync(CancellationToken cancellationToken = default);
}