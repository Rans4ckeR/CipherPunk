namespace CipherPunk.UI;

internal readonly record struct UiRemoteServerTestResult(
    TlsVersion TlsVersion,
    string CipherSuiteId,
    bool Supported,
    string? ErrorReason);