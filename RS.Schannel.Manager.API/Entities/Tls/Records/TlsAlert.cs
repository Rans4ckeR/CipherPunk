namespace RS.Schannel.Manager.API;

public readonly record struct TlsAlert(TlsAlertLevel Level, TlsAlertDescription Description);