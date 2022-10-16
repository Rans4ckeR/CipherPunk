namespace RS.Schannel.Manager.API;

using System.Runtime.Versioning;

public interface IGroupPolicyService
{
    [SupportedOSPlatform("windows")]
    Task<string> GetSslCipherSuiteOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default);

    [SupportedOSPlatform("windows")]
    Task<string> GetSslCurveOrderPolicyWindowsDefaultsAsync(CancellationToken cancellationToken = default);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateSslCipherSuiteOrderPolicy(string[] cipherSuites);

    [SupportedOSPlatform("windows6.0.6000")]
    void UpdateEccCurveOrderPolicy(string[] ellipticCurves);
}