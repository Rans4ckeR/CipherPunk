using System.Collections.Frozen;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace CipherPunk;

internal sealed class SchannelService(IWindowsVersionService windowsVersionService, IWindowsDocumentationService windowsDocumentationService) : ISchannelService
{
    private const string SchannelPath = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\";
    private const string SchannelProtocolsPath = SchannelPath + "Protocols\\";
    private const string SchannelProtocolsClientPath = "\\Client";
    private const string SchannelProtocolsServerPath = "\\Server";
    private const string SchannelKeyExchangeAlgorithmsPath = SchannelPath + "KeyExchangeAlgorithms\\";
    private const string SchannelHashesPath = SchannelPath + "Hashes\\";
    private const string SchannelCiphersPath = SchannelPath + "Ciphers\\";
    private const string SchannelMessagingPath = SchannelPath + "Messaging\\";
    private const string Enabled = "Enabled";
    private const string DisabledByDefault = "DisabledByDefault";
    private const string ClientMinKeyBitLength = "ClientMinKeyBitLength";
    private const string ClientMaxKeyBitLength = "ClientMaxKeyBitLength";
    private const string ServerMinKeyBitLength = "ServerMinKeyBitLength";
    private const string EventLogging = "EventLogging";
    private const string ClientCacheTime = "ClientCacheTime";
    private const string CertificateMappingMethods = "CertificateMappingMethods";
    private const string EnableOcspStaplingForSni = "EnableOcspStaplingForSni";
    private const string IssuerCacheSize = "IssuerCacheSize";
    private const string IssuerCacheTime = "IssuerCacheTime";
    private const string MaximumCacheSize = "MaximumCacheSize";
    private const string MessageLimitClient = "MessageLimitClient";
    private const string MessageLimitServer = "MessageLimitServer";
    private const string MessageLimitServerClientAuth = "MessageLimitServerClientAuth";
    private const string SendTrustedIssuerList = "SendTrustedIssuerList";
    private const string ServerCacheTime = "ServerCacheTime";

    [SupportedOSPlatform("windows")]
    public FrozenSet<SchannelProtocolSettings> GetProtocolSettings()
    {
        var result = new List<SchannelProtocolSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelProtocolsPath);

        foreach (SchannelProtocol schannelProtocol in Enum.GetValues<SchannelProtocol>())
        {
            string subKeyName = GetSchannelProtocolSubKeyName(schannelProtocol);
            using RegistryKey? clientKey = key?.OpenSubKey(FormattableString.Invariant($"{subKeyName}{SchannelProtocolsClientPath}"));
            using RegistryKey? serverKey = key?.OpenSubKey(FormattableString.Invariant($"{subKeyName}{SchannelProtocolsServerPath}"));
            int? clientDisabledByDefault = (int?)clientKey?.GetValue(DisabledByDefault);
            int? serverDisabledByDefault = (int?)serverKey?.GetValue(DisabledByDefault);
            int? clientEnabled = (int?)clientKey?.GetValue(Enabled);
            int? serverEnabled = (int?)serverKey?.GetValue(Enabled);
            SchannelProtocolSettings defaultSchannelProtocolSettings = windowsDocumentationService.GetProtocolConfigurations(windowsVersionService.WindowsVersion).Single(q => q.Protocol == schannelProtocol);
            SchannelProtocolStatus clientStatus = GetProtocolStatus(clientDisabledByDefault, clientEnabled, defaultSchannelProtocolSettings.ClientStatus);
            SchannelProtocolStatus serverStatus = GetProtocolStatus(serverDisabledByDefault, serverEnabled, defaultSchannelProtocolSettings.ServerStatus);

            result.Add(new(schannelProtocol, clientStatus, serverStatus));
        }

        return result.ToFrozenSet();
    }

    [SupportedOSPlatform("windows")]
    public void UpdateProtocolSettings(IEnumerable<SchannelProtocolSettings> schannelProtocolSettings)
    {
        FrozenSet<SchannelProtocolSettings> currentProtocolSettings = GetProtocolSettings();
        using RegistryKey key = Registry.LocalMachine.CreateSubKey(SchannelProtocolsPath);

        foreach (SchannelProtocolSettings schannelProtocolSetting in schannelProtocolSettings)
        {
            SchannelProtocolSettings activeProtocolSettings = currentProtocolSettings.Single(q => q.Protocol == schannelProtocolSetting.Protocol);
            string subKeyName = GetSchannelProtocolSubKeyName(schannelProtocolSetting.Protocol);

            if (schannelProtocolSetting.ClientStatus != activeProtocolSettings.ClientStatus)
            {
                using RegistryKey clientKey = key.CreateSubKey(FormattableString.Invariant($"{subKeyName}{SchannelProtocolsClientPath}"));

                UpdateProtocolSettings(schannelProtocolSetting.ClientStatus, clientKey);
            }

            if (schannelProtocolSetting.ServerStatus != activeProtocolSettings.ServerStatus)
            {
                using RegistryKey serverKey = key.CreateSubKey(FormattableString.Invariant($"{subKeyName}{SchannelProtocolsServerPath}"));

                UpdateProtocolSettings(schannelProtocolSetting.ClientStatus, serverKey);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    public void ResetProtocolSettings() => UpdateProtocolSettings(windowsDocumentationService.GetProtocolConfigurations(windowsVersionService.WindowsVersion));

    [SupportedOSPlatform("windows")]
    public FrozenSet<SchannelKeyExchangeAlgorithmSettings> GetKeyExchangeAlgorithmSettings()
    {
        var result = new List<SchannelKeyExchangeAlgorithmSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelKeyExchangeAlgorithmsPath);
        string[] subKeyNames = key?.GetSubKeyNames() ?? [];

        foreach (string subKeyName in subKeyNames)
        {
            using RegistryKey? subKey = key!.OpenSubKey(subKeyName);
            int? enabled = (int?)subKey?.GetValue(Enabled);
            int? clientMinKeyBitLength = (int?)subKey?.GetValue(ClientMinKeyBitLength);
            int? clientMaxKeyBitLength = (int?)subKey?.GetValue(ClientMaxKeyBitLength);
            int? serverMinKeyBitLength = (int?)subKey?.GetValue(ServerMinKeyBitLength);
            SchannelKeyExchangeAlgorithm schannelKeyExchangeAlgorithm = subKeyName switch
            {
                "Diffie-Hellman" => SchannelKeyExchangeAlgorithm.Diffie_Hellman,
                "ECDH" => SchannelKeyExchangeAlgorithm.ECDH,
                "PKCS" => SchannelKeyExchangeAlgorithm.PKCS,
                _ => throw new ArgumentOutOfRangeException(nameof(subKeyName), subKeyName, null)
            };

            if (windowsVersionService.WindowsVersion >= WindowsVersion.Windows10V1507)
            {
                clientMinKeyBitLength ??= 1024;
                serverMinKeyBitLength ??= 2048;
            }

            result.Add(new(schannelKeyExchangeAlgorithm, clientMinKeyBitLength, clientMaxKeyBitLength, serverMinKeyBitLength, enabled is null ? null : enabled is not 0));
        }

        return result.ToFrozenSet();
    }

    [SupportedOSPlatform("windows")]
    public void UpdateKeyExchangeAlgorithmSettings(IEnumerable<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings) => throw new NotImplementedException();

    [SupportedOSPlatform("windows")]
    public void ResetKeyExchangeAlgorithmSettings() => throw new NotImplementedException();

    [SupportedOSPlatform("windows")]
    public FrozenSet<SchannelHashSettings> GetSchannelHashSettings()
    {
        var result = new List<SchannelHashSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelHashesPath);
        string[] subKeyNames = key?.GetSubKeyNames() ?? [];

        foreach (string subKeyName in subKeyNames)
        {
            using RegistryKey? subKey = key!.OpenSubKey(subKeyName);
            int? enabled = (int?)subKey?.GetValue(Enabled);
            SchannelHash schannelHash = subKeyName switch
            {
                "MD5" => SchannelHash.MD5,
                "SHA" => SchannelHash.SHA1,
                "SHA256" => SchannelHash.SHA256,
                "SHA384" => SchannelHash.SHA384,
                "SHA512" => SchannelHash.SHA512,
                "SHA3-256" => SchannelHash.SHA3_256,
                "SHA3-384" => SchannelHash.SHA3_384,
                "SHA3-512" => SchannelHash.SHA3_512,
                "SHAKE128" => SchannelHash.SHAKE128,
                "SHAKE256" => SchannelHash.SHAKE256,
                "CSHAKE128" => SchannelHash.CSHAKE128,
                "CSHAKE256" => SchannelHash.CSHAKE256,
                "KMAC128" => SchannelHash.KMAC128,
                "KMAC256" => SchannelHash.KMAC256,
                _ => throw new ArgumentOutOfRangeException(nameof(subKeyName), subKeyName, null)
            };

            result.Add(new(schannelHash, enabled is null ? null : enabled is not 0));
        }

        return result.ToFrozenSet();
    }

    [SupportedOSPlatform("windows")]
    public void UpdateSchannelHashSettings(IEnumerable<SchannelHashSettings> schannelHashSettings) => throw new NotImplementedException();

    [SupportedOSPlatform("windows")]
    public void ResetSchannelHashSettings() => throw new NotImplementedException();

    [SupportedOSPlatform("windows")]
    public FrozenSet<SchannelCipherSettings> GetSchannelCipherSettings()
    {
        var result = new List<SchannelCipherSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelCiphersPath);
        string[] subKeyNames = key?.GetSubKeyNames() ?? [];

        foreach (string subKeyName in subKeyNames)
        {
            using RegistryKey? subKey = key!.OpenSubKey(subKeyName);
            int? enabled = (int?)subKey?.GetValue(Enabled);
            SchannelCipher schannelCipher = subKeyName switch
            {
                "AES 128/128" => SchannelCipher.AES_128,
                "AES 256/256" => SchannelCipher.AES_256,
                "DES 56/56" => SchannelCipher.DES56,
                "NULL" => SchannelCipher.NULL,
                "RC2 128/128" => SchannelCipher.RC2_128,
                "RC2 40/128" => SchannelCipher.RC2_40,
                "RC2 56/128" => SchannelCipher.RC2_56,
                "RC4 128/128" => SchannelCipher.RC4_128,
                "RC4 40/128" => SchannelCipher.RC4_40,
                "RC4 56/128" => SchannelCipher.RC4_56,
                "RC4 64/128" => SchannelCipher.RC4_64,
                "Triple DES 168" => SchannelCipher.TRIPLE_DES_168,
                _ => throw new ArgumentOutOfRangeException(nameof(subKeyName), subKeyName, null)
            };

            result.Add(new(schannelCipher, enabled is null ? null : enabled is not 0));
        }

        return result.ToFrozenSet();
    }

    [SupportedOSPlatform("windows")]
    public void UpdateSchannelCipherSettings(IEnumerable<SchannelCipherSettings> schannelCipherSettings) => throw new NotImplementedException();

    [SupportedOSPlatform("windows")]
    public void ResetSchannelCipherSettings() => throw new NotImplementedException();

    [SupportedOSPlatform("windows")]
    public SchannelSettings GetSchannelSettings()
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelPath);
        var eventLogging = (SchannelEventLogging?)(int?)key?.GetValue(EventLogging);
        var certificateMappingMethods = (SchannelCertificateMappingMethod?)(int?)key?.GetValue(CertificateMappingMethods);
        int? clientCacheTime = (int?)key?.GetValue(ClientCacheTime);
        int? enableOcspStaplingForSni = (int?)key?.GetValue(EnableOcspStaplingForSni);
        int? issuerCacheSize = (int?)key?.GetValue(IssuerCacheSize);
        int? issuerCacheTime = (int?)key?.GetValue(IssuerCacheTime);
        int? maximumCacheSize = (int?)key?.GetValue(MaximumCacheSize);
        int? sendTrustedIssuerList = (int?)key?.GetValue(SendTrustedIssuerList);
        int? serverCacheTime = (int?)key?.GetValue(ServerCacheTime);
        using RegistryKey? messagingSubKey = Registry.LocalMachine.OpenSubKey(SchannelMessagingPath);
        int? messageLimitClient = (int?)messagingSubKey?.GetValue(MessageLimitClient);
        int? messageLimitServer = (int?)messagingSubKey?.GetValue(MessageLimitServer);
        int? messageLimitServerClientAuth = (int?)messagingSubKey?.GetValue(MessageLimitServerClientAuth);

        return new(
            eventLogging ?? SchannelEventLogging.Error,
            certificateMappingMethods ?? SchannelCertificateMappingMethod.S4U2Self | SchannelCertificateMappingMethod.S4U2SelfExplicit,
            clientCacheTime ?? (int)TimeSpan.FromHours(10).TotalMilliseconds,
            enableOcspStaplingForSni is not null and not 0,
            issuerCacheSize ?? 100,
            issuerCacheTime ?? (int)TimeSpan.FromMinutes(10).TotalMilliseconds,
            maximumCacheSize ?? 20000,
            sendTrustedIssuerList is null ? windowsVersionService.WindowsVersion <= WindowsVersion.Windows7OrServer2008R2 : sendTrustedIssuerList is not 0,
            serverCacheTime ?? (int)TimeSpan.FromHours(10).TotalMilliseconds,
            messageLimitClient ?? 0x8000,
            messageLimitServer ?? 0x4000,
            messageLimitServerClientAuth ?? 0x8000);
    }

    [SupportedOSPlatform("windows")]
    public void UpdateSchannelSettings(SchannelSettings schannelSettings)
    {
        using RegistryKey key = Registry.LocalMachine.CreateSubKey(SchannelPath);

        if (schannelSettings.EventLogging.HasValue)
            key.SetValue(EventLogging, schannelSettings.EventLogging, RegistryValueKind.DWord);
        else
            key.DeleteValue(EventLogging, false);

        if (schannelSettings.CertificateMappingMethods.HasValue)
            key.SetValue(CertificateMappingMethods, schannelSettings.CertificateMappingMethods, RegistryValueKind.DWord);
        else
            key.DeleteValue(CertificateMappingMethods, false);

        if (schannelSettings.ClientCacheTime.HasValue)
            key.SetValue(ClientCacheTime, schannelSettings.ClientCacheTime, RegistryValueKind.DWord);
        else
            key.DeleteValue(ClientCacheTime, false);

        if (schannelSettings.EnableOcspStaplingForSni.HasValue)
            key.SetValue(EnableOcspStaplingForSni, schannelSettings.EnableOcspStaplingForSni, RegistryValueKind.DWord);
        else
            key.DeleteValue(EnableOcspStaplingForSni, false);

        if (schannelSettings.IssuerCacheSize.HasValue)
            key.SetValue(IssuerCacheSize, schannelSettings.IssuerCacheSize, RegistryValueKind.DWord);
        else
            key.DeleteValue(IssuerCacheSize, false);

        if (schannelSettings.IssuerCacheTime.HasValue)
            key.SetValue(IssuerCacheTime, schannelSettings.IssuerCacheTime, RegistryValueKind.DWord);
        else
            key.DeleteValue(IssuerCacheTime, false);

        if (schannelSettings.MaximumCacheSize.HasValue)
            key.SetValue(MaximumCacheSize, schannelSettings.MaximumCacheSize, RegistryValueKind.DWord);
        else
            key.DeleteValue(MaximumCacheSize, false);

        if (schannelSettings.SendTrustedIssuerList.HasValue)
            key.SetValue(SendTrustedIssuerList, schannelSettings.SendTrustedIssuerList, RegistryValueKind.DWord);
        else
            key.DeleteValue(SendTrustedIssuerList, false);

        if (schannelSettings.ServerCacheTime.HasValue)
            key.SetValue(ServerCacheTime, schannelSettings.ServerCacheTime, RegistryValueKind.DWord);
        else
            key.DeleteValue(ServerCacheTime, false);

        using RegistryKey messagingSubKey = Registry.LocalMachine.CreateSubKey(SchannelMessagingPath);

        if (schannelSettings.MessageLimitClient.HasValue)
            messagingSubKey.SetValue(MessageLimitClient, schannelSettings.MessageLimitClient, RegistryValueKind.DWord);
        else
            messagingSubKey.DeleteValue(MessageLimitClient, false);

        if (schannelSettings.MessageLimitServer.HasValue)
            messagingSubKey.SetValue(MessageLimitServer, schannelSettings.MessageLimitServer, RegistryValueKind.DWord);
        else
            messagingSubKey.DeleteValue(MessageLimitServer, false);

        if (schannelSettings.MessageLimitServerClientAuth.HasValue)
            messagingSubKey.SetValue(MessageLimitServerClientAuth, schannelSettings.MessageLimitServerClientAuth, RegistryValueKind.DWord);
        else
            messagingSubKey.DeleteValue(MessageLimitServerClientAuth, false);
    }

    [SupportedOSPlatform("windows")]
    public void ResetSchannelSettings() => UpdateSchannelSettings(default(SchannelSettings) with { EventLogging = SchannelEventLogging.Error });

    private static SchannelProtocolStatus GetProtocolStatus(int? disabledByDefault, int? enabled, SchannelProtocolStatus defaultSchannelProtocolStatus)
    {
        if (defaultSchannelProtocolStatus is SchannelProtocolStatus.NotSupported)
            return SchannelProtocolStatus.NotSupported;

        if (enabled is not null and not 0 && disabledByDefault is 0)
            return SchannelProtocolStatus.Enabled;

#pragma warning disable IDE0046 // Use conditional expression for return
        if (enabled is not null and not 0 && disabledByDefault is not null and not 0)
#pragma warning restore IDE0046 // Use conditional expression for return
            return SchannelProtocolStatus.DisabledByDefault;

        return enabled is 0 ? SchannelProtocolStatus.Disabled : defaultSchannelProtocolStatus;
    }

    private static string GetSchannelProtocolSubKeyName(SchannelProtocol schannelProtocol)
        => schannelProtocol switch
        {
            SchannelProtocol.DTLS1_0 => "DTLS 1.0",
            SchannelProtocol.DTLS1_2 => "DTLS 1.2",
            SchannelProtocol.DTLS1_3 => "DTLS 1.3",
            SchannelProtocol.UNIHELLO => "Multi-Protocol Unified Hello",
            SchannelProtocol.PCT1_0 => "PCT 1.0",
            SchannelProtocol.SSL2_0 => "SSL 2.0",
            SchannelProtocol.SSL3_0 => "SSL 3.0",
            SchannelProtocol.TLS1_0 => "TLS 1.0",
            SchannelProtocol.TLS1_1 => "TLS 1.1",
            SchannelProtocol.TLS1_2 => "TLS 1.2",
            SchannelProtocol.TLS1_3 => "TLS 1.3",
            _ => throw new ArgumentOutOfRangeException(nameof(schannelProtocol), schannelProtocol, null)
        };

    [SupportedOSPlatform("windows")]
    private static void UpdateProtocolSettings(SchannelProtocolStatus schannelProtocolStatus, RegistryKey key)
    {
        int? disabledByDefault;
        int? enabled;
        const int trueValue = unchecked((int)0xFF_FF_FF_FF);
        const int falseValue = 0;

        switch (schannelProtocolStatus)
        {
            case SchannelProtocolStatus.Enabled:
                enabled = trueValue;
                disabledByDefault = falseValue;
                break;
            case SchannelProtocolStatus.DisabledByDefault:
                enabled = trueValue;
                disabledByDefault = trueValue;
                break;
            case SchannelProtocolStatus.Disabled:
                enabled = falseValue;
                disabledByDefault = trueValue;
                break;
            case SchannelProtocolStatus.OsDefault:
            case SchannelProtocolStatus.NotSupported:
                enabled = null;
                disabledByDefault = null;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(schannelProtocolStatus), schannelProtocolStatus, null);
        }

        if (disabledByDefault is null)
            key.DeleteValue(DisabledByDefault);
        else
            key.SetValue(DisabledByDefault, disabledByDefault, RegistryValueKind.DWord);

        if (enabled is null)
            key.DeleteValue(DisabledByDefault);
        else
            key.SetValue(Enabled, enabled, RegistryValueKind.DWord);
    }
}