namespace CipherPunk;

using System.Collections.Frozen;
using System.Runtime.Versioning;

public interface ISchannelLogService
{
    [SupportedOSPlatform("windows")]
    FrozenSet<SchannelLog> GetSchannelLogs();
}