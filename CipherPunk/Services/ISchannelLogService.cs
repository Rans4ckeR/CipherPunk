using System.Runtime.Versioning;

namespace CipherPunk;

public interface ISchannelLogService
{
    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    IReadOnlyCollection<SchannelLog> GetSchannelLogs();
#pragma warning restore CA1024 // Use properties where appropriate
}