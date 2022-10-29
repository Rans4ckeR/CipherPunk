﻿namespace CipherPunk;

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;

internal sealed class SchannelLogService : ISchannelLogService
{
    [SupportedOSPlatform("windows")]
    public List<SchannelLog> GetSchannelLogs()
    {
        // https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786445(v=ws.11)
        var result = new List<SchannelLog>();
        EventLogEntryCollection systemEventLogEntries = EventLog.GetEventLogs().Single(q => "System".Equals(q.LogDisplayName, StringComparison.OrdinalIgnoreCase)).Entries;
        var schannelEventLogEntries = new List<(SchannelLog SchannelLog, int ProcessId)>();

        for (int i = systemEventLogEntries.Count - 1; i > -1; i--)
        {
            using EventLogEntry eventLogEntry = systemEventLogEntries[i];

            if (!"Schannel".Equals(eventLogEntry.Source, StringComparison.OrdinalIgnoreCase))
                continue;

            string message = eventLogEntry.Message;
            DateTime timeGenerated = eventLogEntry.TimeGenerated;
            int processId = int.Parse(eventLogEntry.ReplacementStrings[0], CultureInfo.InvariantCulture);
            string processName = eventLogEntry.ReplacementStrings[1];
            string? tlsVersion = null;
            string? processType = null;
            string? errorCode = null;

            if (eventLogEntry.InstanceId == 36874)
            {
                tlsVersion = eventLogEntry.ReplacementStrings[2];
            }
            else if (eventLogEntry.InstanceId == 36871)
            {
                processType = eventLogEntry.ReplacementStrings[2];
                errorCode = eventLogEntry.ReplacementStrings[3];
            }

            schannelEventLogEntries.Add((new(message, timeGenerated, processId, processName, processType, tlsVersion, errorCode, null, null, null), processId));
        }

        foreach (int processId in schannelEventLogEntries.Select(q => q.ProcessId).Distinct())
        {
            Process? process = null;

            try
            {
                process = Process.GetProcessById(processId);
            }
            catch (ArgumentException)
            {
            }

            if (process is null)
                continue;

            using (process)
            {
                string processCurrentName = process.ProcessName;
                string processMainWindowTitle = process.MainWindowTitle;
                string? processMainModuleFileName = process.MainModule?.FileName;

                result.AddRange(schannelEventLogEntries.Where(q => q.ProcessId == processId).Select(q => q.SchannelLog with
                {
                    ProcessCurrentName = processCurrentName,
                    ProcessMainWindowTitle = processMainWindowTitle,
                    ProcessMainModuleFileName = processMainModuleFileName
                }));
            }
        }

        return schannelEventLogEntries.Where(q => !result.Select(r => r.ProcessId).Contains(q.ProcessId)).Select(q => q.SchannelLog).Concat(result).OrderByDescending(q => q.TimeGenerated).ToList();
    }
}