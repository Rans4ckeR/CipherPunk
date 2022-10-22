namespace RS.Schannel.Manager.API;

public interface ITlsService
{
    WindowsSchannelVersion GetWindowsSchannelVersion();

    Task<List<(TlsVersion, List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>?)>> GetRemoteServerCipherSuitesAsync(string hostName, CancellationToken cancellationToken);

    Task<List<(uint CipherSuiteId, bool Supported, TlsAlert? ErrorReason)>> GetRemoteServerCipherSuitesAsync(string hostName, TlsVersion tlsVersion, CancellationToken cancellationToken);
}