namespace CipherPunk;

public readonly record struct SchannelLog(
    string Message,
    DateTime TimeGenerated,
    int ProcessId,
    string ProcessName,
    string? ProcessType,
    string? TlsVersion,
    string? ErrorCode,
    string? ProcessCurrentName,
    string? ProcessMainWindowTitle,
    string? ProcessMainModuleFileName);