namespace CipherPunk;

using System.Runtime.Versioning;

public interface IGroupPolicyService
{
    [SupportedOSPlatform("windows")]
    ValueTask<string[]> GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default);

    [SupportedOSPlatform("windows")]
    ValueTask<string[]> GetSslCurveOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateSslCipherSuiteOrderPolicy(IEnumerable<string> cipherSuites);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateEccCurveOrderPolicy(IEnumerable<string> ellipticCurves);

    [SupportedOSPlatform("windows6.0.6000")]
    string[] GetSslCipherSuiteOrderPolicy();

    [SupportedOSPlatform("windows6.0.6000")]
    string[] GetEccCurveOrderPolicy();
}