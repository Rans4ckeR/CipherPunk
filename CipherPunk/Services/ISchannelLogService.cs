using System.Collections.Frozen;
using System.Runtime.Versioning;

namespace CipherPunk;

public interface ISchannelLogService
{
    [SupportedOSPlatform("windows")]
#pragma warning disable CA1024 // Use properties where appropriate
    FrozenSet<SchannelLog> GetSchannelLogs();
#pragma warning restore CA1024 // Use properties where appropriate
}