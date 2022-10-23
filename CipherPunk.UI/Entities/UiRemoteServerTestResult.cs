namespace CipherPunk.UI;

using CipherPunk;

internal readonly record struct UiRemoteServerTestResult(
    TlsVersion TlsVersion,
    string CipherSuiteId,
    bool Supported,
    string? ErrorReason);