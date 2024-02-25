namespace CipherPunk;

using System.Collections.Frozen;

public interface ITlsService
{
    ValueTask<FrozenSet<(TlsVersion TlsVersion, FrozenSet<(uint CipherSuiteId, bool Supported, string? ErrorReason)>? Results)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, CancellationToken cancellationToken = default);

    ValueTask<FrozenSet<(uint CipherSuiteId, bool Supported, string? ErrorReason)>> GetRemoteServerCipherSuitesAsync(string hostName, ushort port, TlsVersion tlsVersion, CancellationToken cancellationToken = default);
}