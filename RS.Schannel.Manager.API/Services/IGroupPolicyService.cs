namespace RS.Schannel.Manager.API;

public interface IGroupPolicyService
{
    Task<string> GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default);

    Task<string> GetSslCurveOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default);

    void UpdateSslCipherSuiteOrderPolicy(string[] cipherSuites);

    void UpdateEccCurveOrderPolicy(string[] ellipticCurves);
}