namespace RS.Schannel.Manager.UI;

using RS.Schannel.Manager.API;

internal readonly record struct UiRemoteServerTestResult(
    TlsVersion TlsVersion,
    string CipherSuiteId,
    bool Supported,
    string? ErrorReason);