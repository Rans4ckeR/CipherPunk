namespace RS.Schannel.Manager.API;

public interface IGroupPolicyService
{
    void UpdateSslCipherSuiteOrderPolicy(string[] cipherSuites);

    void UpdateEccCurveOrderPolicy(string[] eccCurves);
}