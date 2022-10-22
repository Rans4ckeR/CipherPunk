namespace RS.Schannel.Manager.API;

public interface ITlsService
{
    WindowsSchannelVersion GetWindowsSchannelVersion();

    ValueTask<List<(TlsVersion TlsVersion, List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, CancellationToken cancellationToken = default);

    ValueTask<List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, TlsVersion tlsVersion, CancellationToken cancellationToken = default);
}