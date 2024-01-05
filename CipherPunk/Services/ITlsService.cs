namespace CipherPunk;

public interface ITlsService
{
    WindowsVersion GetWindowsVersion();

    ValueTask<List<(TlsVersion TlsVersion, List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, CancellationToken cancellationToken = default);

    ValueTask<List<(uint CipherSuiteId, bool Supported, string? ErrorReason)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, TlsVersion tlsVersion, CancellationToken cancellationToken = default);
}