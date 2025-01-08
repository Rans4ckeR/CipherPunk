using System.Collections.Frozen;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;

namespace CipherPunk;

internal sealed class CipherSuiteService(IWindowsDocumentationService windowsDocumentationService, IWindowsVersionService windowsVersionService)
    : ICipherSuiteService
{
    private const string LocalCngSslContextName = "SSL";
    private const string NcryptSchannelInterfaceSslKey = @"SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002";
    private const string SslCipherSuiteOrderValueName = "Functions";

    private readonly IWindowsDocumentationService windowsDocumentationService = windowsDocumentationService;
    private readonly IWindowsVersionService windowsVersionService = windowsVersionService;

    [SupportedOSPlatform("windows6.0.6000")]
    public IEnumerable<string> GetLocalCngConfigurationContextIdentifiers()
    {
        uint pcbBuffer = 0U;
        string[] contexts;

        unsafe
        {
            CRYPT_CONTEXTS* ppBuffer = null;

            try
            {
                NTSTATUS status = PInvoke.BCryptEnumContexts(BCRYPT_TABLE.CRYPT_LOCAL, ref pcbBuffer, &ppBuffer);

                if (status.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(status);

                ref CRYPT_CONTEXTS cryptContexts = ref Unsafe.AsRef<CRYPT_CONTEXTS>(ppBuffer);

                contexts = new string[cryptContexts.cContexts];

                for (uint i = uint.MinValue; i < cryptContexts.cContexts; i++)
                {
                    PWSTR pStr = cryptContexts.rgpszContexts[i];

                    contexts[i] = pStr.ToString();
                }
            }
            finally
            {
                PInvoke.BCryptFreeBuffer(ppBuffer);
            }
        }

        return contexts;
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public FrozenSet<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList()
        => windowsDocumentationService.GetCipherSuiteConfigurations(windowsVersionService.WindowsVersion);

    [SupportedOSPlatform("windows6.0.6000")]
    public FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemConfiguredCipherSuiteList()
    {
        using RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey(NcryptSchannelInterfaceSslKey);
        string[] configuredCipherSuites = (string[]?)registryKey?.GetValue(SslCipherSuiteOrderValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) ?? [];
        FrozenSet<WindowsApiCipherSuiteConfiguration> availableWindowsApiActiveEllipticCurveConfigurations = GetOperatingSystemDefaultCipherSuiteList();
        ushort priority = ushort.MinValue;

        return [.. configuredCipherSuites.Select(q => availableWindowsApiActiveEllipticCurveConfigurations.Single(r => r.CipherSuite.ToString().Equals(q, StringComparison.OrdinalIgnoreCase))).Select(q => q with { Priority = ++priority })];
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList()
    {
        uint pcbBuffer = 0U;
        IEnumerable<string> contexts = GetLocalCngConfigurationContextIdentifiers();

        if (!contexts.Contains(LocalCngSslContextName, StringComparer.OrdinalIgnoreCase))
            throw new SchannelServiceException(FormattableString.Invariant($"{LocalCngSslContextName} context not found."));

        unsafe
        {
            CRYPT_CONTEXT_FUNCTIONS* ppBuffer = null;

            try
            {
                NTSTATUS bCryptEnumContextFunctionsStatus = PInvoke.BCryptEnumContextFunctions(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, ref pcbBuffer, &ppBuffer);

                if (bCryptEnumContextFunctionsStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptEnumContextFunctionsStatus);

                FrozenSet<WindowsApiCipherSuiteConfiguration> defaultCipherSuiteConfigurations = GetOperatingSystemDefaultCipherSuiteList();
                var cipherSuiteConfigurations = new List<WindowsApiCipherSuiteConfiguration>();
                ref CRYPT_CONTEXT_FUNCTIONS cryptContextFunctions = ref Unsafe.AsRef<CRYPT_CONTEXT_FUNCTIONS>(ppBuffer);

                for (uint i = uint.MinValue; i < cryptContextFunctions.cFunctions; i++)
                {
                    string? function = cryptContextFunctions.rgpszFunctions[i].ToString();
                    WindowsApiCipherSuiteConfiguration cipherSuite = defaultCipherSuiteConfigurations.SingleOrDefault(q => function.Equals(q.CipherSuiteName, StringComparison.OrdinalIgnoreCase)) with { Priority = (ushort)(i + 1) };

                    if (cipherSuite == default)
                        throw new SchannelServiceException(function);
                    else
                        cipherSuiteConfigurations.Add(cipherSuite);
                }

                return [.. cipherSuiteConfigurations];
            }
            finally
            {
                if (ppBuffer is not null)
                    PInvoke.BCryptFreeBuffer(ppBuffer);
            }
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public FrozenSet<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList()
    {
        var cipherSuiteConfigurations = new List<WindowsApiCipherSuiteConfiguration?>();

        unsafe
        {
            uint pcbBuffer = 0U;
            CRYPT_PROVIDER_REFS* ppBuffer = null;
            string? pszProvider;
            string? pszImage;

            try
            {
                NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders(LocalCngSslContextName, (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, null, null, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, BCRYPT_RESOLVE_PROVIDERS_FLAGS.CRYPT_ALL_PROVIDERS, ref pcbBuffer, &ppBuffer);

                if (bCryptResolveProvidersStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptResolveProvidersStatus);

                ref CRYPT_PROVIDER_REFS cryptProviderRefs = ref Unsafe.AsRef<CRYPT_PROVIDER_REFS>(ppBuffer);

                if (cryptProviderRefs.cProviders is not 1U)
                    throw new SchannelServiceException(FormattableString.Invariant($"Found {cryptProviderRefs.cProviders} providers, expected 1."));

                ref CRYPT_PROVIDER_REF cryptProviderRef = ref Unsafe.AsRef<CRYPT_PROVIDER_REF>(cryptProviderRefs.rgpProviders[0]);
                pszProvider = cryptProviderRef.pszProvider.ToString();
                string? pszFunction = cryptProviderRef.pszFunction.ToString();
                uint cProperties = cryptProviderRef.cProperties;
                uint dwInterface = cryptProviderRef.dwInterface;
                ref CRYPT_IMAGE_REF userModeCryptImageRef = ref Unsafe.AsRef<CRYPT_IMAGE_REF>(cryptProviderRef.pUM);
                pszImage = userModeCryptImageRef.pszImage.ToString();
                CRYPT_IMAGE_REF_FLAGS dwFlags = userModeCryptImageRef.dwFlags;
            }
            finally
            {
                PInvoke.BCryptFreeBuffer(ppBuffer);
            }

            HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle phSslProvider, pszProvider!);

            using (phSslProvider)
            {
                if (sslOpenProviderResult.Failed)
                    throw new Win32Exception(sslOpenProviderResult);

                HRESULT? sslEnumCipherSuitesResult = null;
                void* ppEnumState = null;

                try
                {
                    while (sslEnumCipherSuitesResult?.Value != HRESULT.NTE_NO_MORE_ITEMS)
                    {
                        NCRYPT_SSL_CIPHER_SUITE* ppCipherSuite = null;

                        try
                        {
                            sslEnumCipherSuitesResult = PInvoke.SslEnumCipherSuites(phSslProvider, null, out ppCipherSuite, ref ppEnumState);

                            if (sslEnumCipherSuitesResult.Value.Succeeded)
                            {
                                ref NCRYPT_SSL_CIPHER_SUITE ncryptSslCipherSuite = ref Unsafe.AsRef<NCRYPT_SSL_CIPHER_SUITE>(ppCipherSuite);
                                SslProviderCipherSuiteId dwCipherSuite = ncryptSslCipherSuite.dwCipherSuite;
                                SslProviderProtocolId dwProtocol = ncryptSslCipherSuite.dwProtocol;
                                WindowsApiCipherSuiteConfiguration? windowsApiCipherSuiteConfiguration = cipherSuiteConfigurations.SingleOrDefault(q => q!.Value.CipherSuite == dwCipherSuite, null);

                                if (windowsApiCipherSuiteConfiguration.HasValue)
                                {
                                    windowsApiCipherSuiteConfiguration.Value.Protocols.Add(dwProtocol);

                                    continue;
                                }

                                var providerProtocolIds = new List<SslProviderProtocolId> { ncryptSslCipherSuite.dwProtocol };
                                string? keyExchangeAlgorithm = null;
                                uint? minimumKeyExchangeKeyLengthBits = null;
                                uint? maximumKeyExchangeKeyLengthBits = null;
                                string? hash = null;
                                uint? hashLengthBytes = null;
                                string? serverCertificateKeyType = null;
                                SslProviderKeyTypeId? keyType = null;
                                string? szExchange = ncryptSslCipherSuite.szExchange.ToString();

                                if (!string.IsNullOrWhiteSpace(szExchange))
                                {
                                    keyExchangeAlgorithm = szExchange;
                                    minimumKeyExchangeKeyLengthBits = ncryptSslCipherSuite.dwMinExchangeLen;
                                    maximumKeyExchangeKeyLengthBits = ncryptSslCipherSuite.dwMaxExchangeLen;
                                }

                                string? szHash = ncryptSslCipherSuite.szHash.ToString();

                                if (!string.IsNullOrWhiteSpace(szHash))
                                {
                                    hash = szHash;
                                    hashLengthBytes = ncryptSslCipherSuite.dwHashLen;
                                }

                                string? szCertificate = ncryptSslCipherSuite.szCertificate.ToString();

                                if (!string.IsNullOrWhiteSpace(szCertificate))
                                    serverCertificateKeyType = szCertificate;

                                SslProviderKeyTypeId dwKeyType = ncryptSslCipherSuite.dwKeyType;

                                if (dwKeyType is not 0)
                                    keyType = dwKeyType;

                                var cipherSuiteConfiguration = new WindowsApiCipherSuiteConfiguration(
                                    0,
                                    providerProtocolIds,
                                    keyType,
                                    serverCertificateKeyType,
                                    maximumKeyExchangeKeyLengthBits,
                                    minimumKeyExchangeKeyLengthBits,
                                    keyExchangeAlgorithm,
                                    hashLengthBytes,
                                    hash,
                                    ncryptSslCipherSuite.dwCipherBlockLen,
                                    ncryptSslCipherSuite.dwCipherLen,
                                    ncryptSslCipherSuite.dwBaseCipherSuite,
                                    dwCipherSuite,
                                    ncryptSslCipherSuite.szCipher.ToString(),
                                    pszProvider,
                                    pszImage,
                                    ncryptSslCipherSuite.szCipherSuite.ToString());

                                cipherSuiteConfigurations.Add(cipherSuiteConfiguration);
                            }
                            else if (sslEnumCipherSuitesResult != HRESULT.NTE_NO_MORE_ITEMS)
                            {
                                throw new Win32Exception(sslEnumCipherSuitesResult.Value);
                            }
                        }
                        finally
                        {
                            if (ppCipherSuite is not null)
                                _ = PInvoke.SslFreeBuffer(ppCipherSuite);
                        }
                    }
                }
                finally
                {
                    if (ppEnumState is not null)
                        _ = PInvoke.SslFreeBuffer(ppEnumState);
                }
            }
        }

        return [.. cipherSuiteConfigurations.Select(static q => q!.Value)];
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void ResetCipherSuiteListToOperatingSystemDefault()
    {
        FrozenSet<WindowsApiCipherSuiteConfiguration> activeCipherSuites = GetOperatingSystemActiveCipherSuiteList();
        IEnumerable<string> defaultCipherSuites = GetOperatingSystemDocumentationDefaultCipherSuiteList()
            .Where(static q => q.EnabledByDefault)
            .OrderBy(static q => q.Priority)
            .Select(static q => q.CipherSuite.ToString());

        foreach (string cipher in activeCipherSuites.Select(static q => q.CipherSuiteName))
        {
            RemoveCipherSuite(cipher);
        }

        foreach (string cipher in defaultCipherSuites)
        {
            AddCipherSuite(cipher, false);
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void RemoveCipherSuite(string cipherSuite)
    {
        NTSTATUS status = PInvoke.BCryptRemoveContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite);

        if (status == NTSTATUS.STATUS_ACCESS_DENIED)
            throw new UnauthorizedAccessException();

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite) => RemoveCipherSuite(cipherSuite.ToString());

    [SupportedOSPlatform("windows6.0.6000")]
    public void AddCipherSuite(string cipherSuite, bool top = true)
    {
        NTSTATUS status = PInvoke.BCryptAddContextFunction(
            BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite, (uint)(top ? PriorityListPosition.CRYPT_PRIORITY_TOP : PriorityListPosition.CRYPT_PRIORITY_BOTTOM));

        if (status == NTSTATUS.STATUS_ACCESS_DENIED)
            throw new UnauthorizedAccessException();

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void AddCipherSuite(SslProviderCipherSuiteId cipherSuite) => AddCipherSuite(cipherSuite.ToString());

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateCipherSuiteOrder(IEnumerable<string> cipherSuites)
    {
        FrozenSet<WindowsApiCipherSuiteConfiguration> activeCipherSuites = GetOperatingSystemActiveCipherSuiteList();

        foreach (string cipher in activeCipherSuites.Select(static q => q.CipherSuiteName))
        {
            RemoveCipherSuite(cipher);
        }

        foreach (string cipher in cipherSuites)
        {
            AddCipherSuite(cipher, false);
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateCipherSuiteOrder(IEnumerable<SslProviderCipherSuiteId> cipherSuites)
        => UpdateCipherSuiteOrder(cipherSuites.Select(static q => q.ToString()));
}