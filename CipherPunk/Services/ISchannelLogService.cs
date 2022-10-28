namespace CipherPunk;

using System.Runtime.Versioning;

public interface ISchannelLogService
{
    [SupportedOSPlatform("windows")]
    List<SchannelLog> GetSchannelLogs();
}