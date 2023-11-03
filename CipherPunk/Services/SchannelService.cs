namespace CipherPunk;

using System.Collections.Generic;
using System.Runtime.Versioning;
using Microsoft.Win32;

internal sealed class SchannelService : ISchannelService
{
    // https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings
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
    private const string ClientMinKeyBitLength = "ClientMinKeyBitLength"; // Added in Windows 10, version 1507 and Windows Server 2016.
    private const string ClientMaxKeyBitLength = "ClientMaxKeyBitLength"; // Added in Windows 10, version 1507 and Windows Server 2016.
    private const string ServerMinKeyBitLength = "ServerMinKeyBitLength"; // Added in Windows 10, version 1507 and Windows Server 2016.
    private const string EventLogging = "EventLogging";
    private const string ClientCacheTime = "ClientCacheTime";
    private const string CertificateMappingMethods = "CertificateMappingMethods";
    private const string EnableOcspStaplingForSni = "EnableOcspStaplingForSni";
    private const string FipsAlgorithmPolicy = "FIPSAlgorithmPolicy";
    private const string IssuerCacheSize = "IssuerCacheSize";
    private const string IssuerCacheTime = "IssuerCacheTime";
    private const string MaximumCacheSize = "MaximumCacheSize";
    private const string MessageLimitClient = "MessageLimitClient";
    private const string MessageLimitServer = "MessageLimitServer";
    private const string MessageLimitServerClientAuth = "MessageLimitServerClientAuth";
    private const string SendTrustedIssuerList = "SendTrustedIssuerList";
    private const string ServerCacheTime = "ServerCacheTime";

    [SupportedOSPlatform("windows")]
    public List<SchannelProtocolSettings> GetProtocolSettings()
    {
        var result = new List<SchannelProtocolSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelProtocolsPath);

        foreach (SchannelProtocol schannelProtocol in Enum.GetValues<SchannelProtocol>())
        {
            string subKeyName = schannelProtocol switch
            {
                SchannelProtocol.DTLS1_0 => "DTLS 1.0",
                SchannelProtocol.DTLS1_2 => "DTLS 1.2",
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
            using RegistryKey? clientKey = key?.OpenSubKey(subKeyName + SchannelProtocolsClientPath);
            using RegistryKey? serverKey = key?.OpenSubKey(subKeyName + SchannelProtocolsServerPath);
            int? clientDisabledByDefault = (int?)clientKey?.GetValue(DisabledByDefault);
            int? serverDisabledByDefault = (int?)serverKey?.GetValue(DisabledByDefault);
            int? clientEnabled = (int?)clientKey?.GetValue(Enabled);
            int? serverEnabled = (int?)serverKey?.GetValue(Enabled);
            SchannelProtocolStatus clientStatus = GetProtocolStatus(clientDisabledByDefault, clientEnabled);
            SchannelProtocolStatus serverStatus = GetProtocolStatus(serverDisabledByDefault, serverEnabled);

            result.Add(new(schannelProtocol, clientStatus, serverStatus));
        }

        return result;
    }

    [SupportedOSPlatform("windows")]
    public void UpdateProtocolSettings(List<SchannelProtocolSettings> schannelProtocolSettings)
    {
        throw new NotImplementedException();
    }

    [SupportedOSPlatform("windows")]
    public List<SchannelKeyExchangeAlgorithmSettings> GetKeyExchangeAlgorithmSettings()
    {
        var result = new List<SchannelKeyExchangeAlgorithmSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelKeyExchangeAlgorithmsPath);
        string[] subKeyNames = key?.GetSubKeyNames() ?? Array.Empty<string>();

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

            result.Add(new(schannelKeyExchangeAlgorithm, clientMinKeyBitLength, clientMaxKeyBitLength, serverMinKeyBitLength, enabled is null ? null : enabled != 0));
        }

        return result;
    }

    [SupportedOSPlatform("windows")]
    public void UpdateKeyExchangeAlgorithmSettings(List<SchannelKeyExchangeAlgorithmSettings> schannelKeyExchangeAlgorithmSettings)
    {
        throw new NotImplementedException();
    }

    [SupportedOSPlatform("windows")]
    public List<SchannelHashSettings> GetSchannelHashSettings()
    {
        var result = new List<SchannelHashSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelHashesPath);
        string[] subKeyNames = key?.GetSubKeyNames() ?? Array.Empty<string>();

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
                _ => throw new ArgumentOutOfRangeException(nameof(subKeyName), subKeyName, null)
            };

            result.Add(new(schannelHash, enabled is null ? null : enabled != 0));
        }

        return result;
    }

    [SupportedOSPlatform("windows")]
    public void UpdateSchannelHashSettings(List<SchannelHashSettings> schannelHashSettings)
    {
        throw new NotImplementedException();
    }

    [SupportedOSPlatform("windows")]
    public List<SchannelCipherSettings> GetSchannelCipherSettings()
    {
        var result = new List<SchannelCipherSettings>();
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelCiphersPath);
        string[] subKeyNames = key?.GetSubKeyNames() ?? Array.Empty<string>();

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

            result.Add(new(schannelCipher, enabled is null ? null : enabled != 0));
        }

        return result;
    }

    [SupportedOSPlatform("windows")]
    public void UpdateSchannelCipherSettings(List<SchannelCipherSettings> schannelCipherSettings)
    {
        throw new NotImplementedException();
    }

    [SupportedOSPlatform("windows")]
    public SchannelSettings GetSchannelSettings()
    {
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(SchannelPath);
        var logLevel = (SchannelLogLevel?)(int?)key?.GetValue(EventLogging);
        var certificateMappingMethods = (CertificateMappingMethod?)(int?)key?.GetValue(CertificateMappingMethods);
        int? clientCacheTime = (int?)key?.GetValue(ClientCacheTime); // in milliseconds
        int? enableOcspStaplingForSni = (int?)key?.GetValue(EnableOcspStaplingForSni);
        int? fipsAlgorithmPolicy = (int?)key?.GetValue(FipsAlgorithmPolicy);
        int? issuerCacheSize = (int?)key?.GetValue(IssuerCacheSize);
        int? issuerCacheTime = (int?)key?.GetValue(IssuerCacheTime); // in milliseconds
        int? maximumCacheSize = (int?)key?.GetValue(MaximumCacheSize);
        int? sendTrustedIssuerList = (int?)key?.GetValue(SendTrustedIssuerList);
        int? serverCacheTime = (int?)key?.GetValue(ServerCacheTime);
        using RegistryKey? messagingSubKey = Registry.LocalMachine.OpenSubKey(SchannelMessagingPath);
        int? messageLimitClient = (int?)messagingSubKey?.GetValue(MessageLimitClient);
        int? messageLimitServer = (int?)messagingSubKey?.GetValue(MessageLimitServer);
        int? messageLimitServerClientAuth = (int?)messagingSubKey?.GetValue(MessageLimitServerClientAuth);

        return new(
            logLevel,
            certificateMappingMethods,
            clientCacheTime,
            enableOcspStaplingForSni is null ? null : enableOcspStaplingForSni is not 0,
            fipsAlgorithmPolicy is null ? null : fipsAlgorithmPolicy is not 0,
            issuerCacheSize,
            issuerCacheTime,
            maximumCacheSize,
            sendTrustedIssuerList is null ? null : sendTrustedIssuerList is not 0,
            serverCacheTime,
            messageLimitClient,
            messageLimitServer,
            messageLimitServerClientAuth);
    }

    [SupportedOSPlatform("windows")]
    public void UpdateSchannelLogSettings(SchannelLogLevel schannelLogLevel)
    {
        using RegistryKey key = Registry.LocalMachine.OpenSubKey(SchannelPath)!;

        key.SetValue(EventLogging, schannelLogLevel, RegistryValueKind.DWord);
    }

    private static SchannelProtocolStatus GetProtocolStatus(int? disabledByDefault, int? enabled)
    {
        if (enabled is not null and not 0 && disabledByDefault is 0)
            return SchannelProtocolStatus.Enabled;

        if (enabled is not null and not 0 && disabledByDefault is not null and not 0)
            return SchannelProtocolStatus.DisabledByDefault;

        return enabled is 0 ? SchannelProtocolStatus.Disabled : SchannelProtocolStatus.OsDefault;
    }
}