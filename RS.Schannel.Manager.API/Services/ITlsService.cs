namespace RS.Schannel.Manager.API;

using System.Runtime.Versioning;

public interface ITlsService
{
    [SupportedOSPlatform("windows6.0.6000")]
    WindowsSchannelVersion GetWindowsSchannelVersion();

    [SupportedOSPlatform("windows")]
    Task GetRemoteServerCipherSuitesAsync(string hostName, CancellationToken cancellationToken);
}