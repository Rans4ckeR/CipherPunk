namespace CipherPunk;

using System.Collections.Frozen;
using System.Runtime.Versioning;

public interface ISchannelLogService
{
    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<SchannelLog> GetSchannelLogs();
#pragma warning restore CA1024 // Use properties where appropriate
}