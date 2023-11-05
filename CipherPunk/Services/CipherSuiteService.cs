namespace CipherPunk;

using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;

internal sealed class CipherSuiteService(
    IWindowsCipherSuiteDocumentationService windowsCipherSuiteDocumentationService, ITlsService tlsService)
    : ICipherSuiteService
{
    private const string LocalCngSslContextName = "SSL";

    [SupportedOSPlatform("windows6.0.6000")]
    public string[] GetLocalCngConfigurationContextIdentifiers()
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

                CRYPT_CONTEXTS cryptContexts = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<CRYPT_CONTEXTS>(ppBuffer), 1)[0];

                contexts = new string[cryptContexts.cContexts];

                for (uint i = uint.MinValue; i < cryptContexts.cContexts; i++)
                {
                    PWSTR pStr = cryptContexts.rgpszContexts[i];

                    contexts[i] = pStr.ToString();
                }
            }
            finally
            {
                if (ppBuffer is not null)
                    PInvoke.BCryptFreeBuffer(ppBuffer);
            }
        }

        return contexts;
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList()
    {
        WindowsSchannelVersion windowsSchannelVersion = tlsService.GetWindowsSchannelVersion();

        return windowsCipherSuiteDocumentationService.GetWindowsDocumentationCipherSuiteConfigurations(windowsSchannelVersion);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemActiveCipherSuiteList()
    {
        uint pcbBuffer = 0U;
        string[] contexts = GetLocalCngConfigurationContextIdentifiers();

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

                List<WindowsApiCipherSuiteConfiguration> defaultCipherSuiteConfigurations = GetOperatingSystemDefaultCipherSuiteList();
                var cipherSuiteConfigurations = new List<WindowsApiCipherSuiteConfiguration>();
                CRYPT_CONTEXT_FUNCTIONS cryptContextFunctions = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<CRYPT_CONTEXT_FUNCTIONS>(ppBuffer), 1)[0];

                for (uint i = uint.MinValue; i < cryptContextFunctions.cFunctions; i++)
                {
                    string? function = cryptContextFunctions.rgpszFunctions[i].ToString();
                    WindowsApiCipherSuiteConfiguration? cipherSuite = defaultCipherSuiteConfigurations.SingleOrDefault(q => function.Equals(q.CipherSuiteName, StringComparison.OrdinalIgnoreCase));

                    if (cipherSuite is null)
                    {
                        // todo
                    }
                    else
                    {
                        cipherSuiteConfigurations.Add(cipherSuite.Value);
                    }
                }

                return cipherSuiteConfigurations;
            }
            finally
            {
                if (ppBuffer is not null)
                    PInvoke.BCryptFreeBuffer(ppBuffer);
            }
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList()
    {
        var cipherSuiteConfigurations = new List<WindowsApiCipherSuiteConfiguration?>();

        unsafe
        {
            NCRYPT_SSL_CIPHER_SUITE* ppCipherSuite = null;
            void* ppEnumState = null;
            CRYPT_PROVIDER_REFS* ppBuffer = null;

            try
            {
                uint pcbBuffer = 0U;
                NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders(LocalCngSslContextName, (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, null, null, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, BCRYPT_RESOLVE_PROVIDERS_FLAGS.CRYPT_ALL_PROVIDERS, ref pcbBuffer, &ppBuffer);

                if (bCryptResolveProvidersStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptResolveProvidersStatus);

                CRYPT_PROVIDER_REFS cryptProviderRefs = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<CRYPT_PROVIDER_REFS>(ppBuffer), 1)[0];

                if (cryptProviderRefs.cProviders is not 1U)
                    throw new SchannelServiceException(FormattableString.Invariant($"Found {cryptProviderRefs.cProviders} providers, expected 1."));

                CRYPT_PROVIDER_REF cryptProviderRef = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<CRYPT_PROVIDER_REF>(cryptProviderRefs.rgpProviders[0]), 1)[0];
                string? pszProvider = cryptProviderRef.pszProvider.ToString();
                string? pszFunction = cryptProviderRef.pszFunction.ToString();
                uint cProperties = cryptProviderRef.cProperties;
                uint dwInterface = cryptProviderRef.dwInterface;
                CRYPT_IMAGE_REF userModeCryptImageRef = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<CRYPT_IMAGE_REF>(cryptProviderRef.pUM), 1)[0];
                string? pszImage = userModeCryptImageRef.pszImage.ToString();
                CRYPT_IMAGE_REF_FLAGS dwFlags = userModeCryptImageRef.dwFlags;

                PInvoke.BCryptFreeBuffer(ppBuffer);

                ppBuffer = null;

                HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle phSslProvider, pszProvider!);

                if (sslOpenProviderResult.Succeeded)
                {
                    HRESULT? sslEnumCipherSuitesResult = null;

                    while (sslEnumCipherSuitesResult?.Value != HRESULT.NTE_NO_MORE_ITEMS)
                    {
                        sslEnumCipherSuitesResult = PInvoke.SslEnumCipherSuites(phSslProvider, null, out ppCipherSuite, ref ppEnumState);

                        if (sslEnumCipherSuitesResult.Value.Succeeded)
                        {
                            NCRYPT_SSL_CIPHER_SUITE ncryptSslCipherSuite = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<NCRYPT_SSL_CIPHER_SUITE>(ppCipherSuite), 1)[0];
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

                            var cipherSuiteConfiguration = new WindowsApiCipherSuiteConfiguration
                            {
                                Protocols = providerProtocolIds,
                                BaseCipherSuite = ncryptSslCipherSuite.dwBaseCipherSuite,
                                Certificate = serverCertificateKeyType,
                                Cipher = ncryptSslCipherSuite.szCipher.ToString(),
                                CipherBlockLength = ncryptSslCipherSuite.dwCipherBlockLen,
                                CipherLength = ncryptSslCipherSuite.dwCipherLen,
                                CipherSuite = dwCipherSuite,
                                Exchange = keyExchangeAlgorithm,
                                Hash = hash,
                                HashLength = hashLengthBytes,
                                Image = pszImage,
                                KeyType = keyType,
                                MaximumExchangeLength = maximumKeyExchangeKeyLengthBits,
                                MinimumExchangeLength = minimumKeyExchangeKeyLengthBits,
                                Provider = pszProvider,
                                CipherSuiteName = ncryptSslCipherSuite.szCipherSuite.ToString()
                            };

                            cipherSuiteConfigurations.Add(cipherSuiteConfiguration);

                            if (ppCipherSuite is not null)
                            {
                                HRESULT sslFreeBufferResult = PInvoke.SslFreeBuffer(ppCipherSuite);

                                ppCipherSuite = null;

                                if (sslFreeBufferResult.Failed)
                                    throw Marshal.GetExceptionForHR(sslFreeBufferResult)!;
                            }
                        }
                        else if (sslEnumCipherSuitesResult.Value.Value != HRESULT.NTE_NO_MORE_ITEMS)
                        {
                            throw Marshal.GetExceptionForHR(sslEnumCipherSuitesResult.Value)!;
                        }
                    }

                    if (ppEnumState is not null)
                    {
                        HRESULT sslFreeBufferResult = PInvoke.SslFreeBuffer(ppEnumState);

                        ppEnumState = null;

                        if (sslFreeBufferResult.Failed)
                            throw Marshal.GetExceptionForHR(sslFreeBufferResult)!;
                    }
                }
                else
                {
                    throw Marshal.GetExceptionForHR(sslOpenProviderResult)!;
                }
            }
            finally
            {
                if (ppBuffer is not null)
                    PInvoke.BCryptFreeBuffer(ppBuffer);

                if (ppCipherSuite is not null)
                    _ = PInvoke.SslFreeBuffer(ppCipherSuite);

                if (ppEnumState is not null)
                    _ = PInvoke.SslFreeBuffer(ppEnumState);
            }
        }

        cipherSuiteConfigurations.Reverse();

        return cipherSuiteConfigurations.Select(q => q!.Value).ToList();
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void ResetCipherSuiteListToOperatingSystemDefault()
    {
        List<WindowsApiCipherSuiteConfiguration> activeCipherSuites = GetOperatingSystemActiveCipherSuiteList();
        List<WindowsApiCipherSuiteConfiguration> defaultCipherSuites = GetOperatingSystemDefaultCipherSuiteList();

        foreach (string cipher in activeCipherSuites.Select(q => q.CipherSuiteName))
        {
            RemoveCipherSuite(cipher);
        }

        foreach (string cipher in defaultCipherSuites.Select(q => q.CipherSuiteName))
        {
            AddCipherSuite(cipher, false);
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void RemoveCipherSuite(string cipherSuite)
    {
        NTSTATUS status = PInvoke.BCryptRemoveContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite);

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite)
    {
        RemoveCipherSuite(cipherSuite.ToString());
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void AddCipherSuite(string cipherSuite, bool top = true)
    {
        NTSTATUS status = PInvoke.BCryptAddContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite, (uint)(top ? PriorityListPosition.CRYPT_PRIORITY_TOP : PriorityListPosition.CRYPT_PRIORITY_BOTTOM));

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void AddCipherSuite(SslProviderCipherSuiteId cipherSuite)
    {
        AddCipherSuite(cipherSuite.ToString());
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateCipherSuiteOrder(string[] cipherSuites)
    {
        List<WindowsApiCipherSuiteConfiguration> activeCipherSuites = GetOperatingSystemActiveCipherSuiteList();

        foreach (string cipher in activeCipherSuites.Select(q => q.CipherSuiteName))
        {
            RemoveCipherSuite(cipher);
        }

        foreach (string cipher in cipherSuites)
        {
            AddCipherSuite(cipher, false);
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateCipherSuiteOrder(SslProviderCipherSuiteId[] cipherSuites)
    {
        UpdateCipherSuiteOrder(cipherSuites.Select(q => q.ToString()).ToArray());
    }
}