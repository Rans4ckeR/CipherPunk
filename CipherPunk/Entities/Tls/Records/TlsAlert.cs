namespace CipherPunk;

public readonly record struct TlsAlert(TlsAlertLevel Level, TlsAlertDescription Description);