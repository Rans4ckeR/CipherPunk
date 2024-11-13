namespace CipherPunk;

internal sealed class WindowsVersionService : IWindowsVersionService
{
    private WindowsVersion? windowsVersion;

    public WindowsVersion WindowsVersion => windowsVersion ??= GetWindowsVersion();

#pragma warning disable CA1502 // Avoid excessive complexity
    private static WindowsVersion GetWindowsVersion()
#pragma warning restore CA1502 // Avoid excessive complexity
    {
        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 26100))
            return WindowsVersion.Windows11V24H2OrServer2025;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 25398))
            return WindowsVersion.WindowsServer2022V23H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22631))
            return WindowsVersion.Windows11V23H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621))
            return WindowsVersion.Windows11V22H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
            return WindowsVersion.Windows11V21H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348))
            return WindowsVersion.WindowsServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19045))
            return WindowsVersion.Windows10V22H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19044))
            return WindowsVersion.Windows10V21H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19043))
            return WindowsVersion.Windows10V21H1;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19042))
            return WindowsVersion.Windows10OrServer2019V20H2;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041))
            return WindowsVersion.Windows10OrServer2019V2004;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18363))
            return WindowsVersion.Windows10OrServer2019V1909;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362))
            return WindowsVersion.Windows10OrServer2019V1903;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763))
            return WindowsVersion.Windows10V1809OrServer2019;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17134))
            return WindowsVersion.Windows10OrServer2016V1803;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 16299))
            return WindowsVersion.Windows10OrServer2016V1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 15063))
            return WindowsVersion.Windows10V1703;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 14393))
            return WindowsVersion.Windows10V1607OrServer2016;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
            return WindowsVersion.Windows10V1511;

        if (OperatingSystem.IsWindowsVersionAtLeast(10))
            return WindowsVersion.Windows10V1507;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3))
            return WindowsVersion.Windows81OrServer2012R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            return WindowsVersion.Windows8OrServer2012;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 1))
            return WindowsVersion.Windows7OrServer2008R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 0, 6002))
            return WindowsVersion.WindowsServer2008SP2;

#pragma warning disable IDE0046 // Use conditional expression for return
        if (OperatingSystem.IsWindowsVersionAtLeast(6))
#pragma warning restore IDE0046 // Use conditional expression for return
            return WindowsVersion.WindowsVistaOrServer2008;

        throw new SchannelServiceException(FormattableString.Invariant($"Unknown Windows version {Environment.OSVersion.Version}."));
    }
}