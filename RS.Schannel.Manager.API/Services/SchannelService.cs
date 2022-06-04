namespace RS.Schannel.Manager.API;

using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Security.Cryptography;
using Windows.Win32.Foundation;
using Windows.Win32.System.Registry;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal sealed class SchannelService : ISchannelService
{
    private const string LocalCngSslContextName = "SSL";
    private const string SSLConfigurationKey = "SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002";
    private const string SSLCurveOrderValueName = "EccCurves";
    private const ushort ListMaximumCharacters = 1023;

    private readonly IWindowsCipherSuiteDocumentationService windowsCipherSuiteDocumentationService;
    private readonly IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService;

    public SchannelService(IWindowsCipherSuiteDocumentationService windowsCipherSuiteDocumentationService, IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService)
    {
        this.windowsCipherSuiteDocumentationService = windowsCipherSuiteDocumentationService;
        this.windowsEllipticCurveDocumentationService = windowsEllipticCurveDocumentationService;
    }

    public string[] GetLocalCngConfigurationContextIdentifiers()
    {
        uint pcbBuffer = 0U;
        string[] contexts;

        unsafe
        {
            CRYPT_CONTEXTS* ppBuffer = null;
            NTSTATUS status = PInvoke.BCryptEnumContexts(BCRYPT_TABLE.CRYPT_LOCAL, ref pcbBuffer, ref ppBuffer);

            if (status.SeverityCode is not NTSTATUS.Severity.Success)
                throw new Win32Exception(status);

            contexts = new string[ppBuffer->cContexts];

            for (int i = 0; i < ppBuffer->cContexts; i++)
            {
                PWSTR pStr = ppBuffer->rgpszContexts[i];

                contexts[i] = pStr.ToString();
            }

            PInvoke.BCryptFreeBuffer(ppBuffer);
        }

        return contexts;
    }

    public List<WindowsDocumentationCipherSuiteConfiguration> GetOperatingSystemDocumentationDefaultCipherSuiteList()
    {
        WindowsSchannelVersion windowsSchannelVersion = GetWindowsSchannelVersion();

        return windowsCipherSuiteDocumentationService.GetWindowsDocumentationCipherSuiteConfigurations(windowsSchannelVersion);
    }

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
                NTSTATUS bCryptEnumContextFunctionsStatus = PInvoke.BCryptEnumContextFunctions(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, ref pcbBuffer, ref ppBuffer);

                if (bCryptEnumContextFunctionsStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptEnumContextFunctionsStatus);

                List<WindowsApiCipherSuiteConfiguration> cipherSuiteConfigurations = GetOperatingSystemDefaultCipherSuiteList();
                string[] functions = new string[ppBuffer->cFunctions];

                for (int i = 0; i < ppBuffer->cFunctions; i++)
                {
                    functions[i] = ppBuffer->rgpszFunctions[i].ToString();
                }

                return cipherSuiteConfigurations.Where(q => functions.Contains(q.CipherSuiteName, StringComparer.InvariantCultureIgnoreCase)).ToList();
            }
            finally
            {
                if (ppBuffer is not null)
                    PInvoke.BCryptFreeBuffer(ppBuffer);
            }
        }
    }

    public List<WindowsApiCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList()
    {
        var cipherSuiteConfigurations = new List<WindowsApiCipherSuiteConfiguration?>();

        unsafe
        {
            NCRYPT_SSL_CIPHER_SUITE* ppCipherSuite = null;
            void* ppEnumState = null;

            try
            {
                uint pcbBuffer = 0U;
                CRYPT_PROVIDER_REFS* ppBuffer = null;
                NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders(LocalCngSslContextName, (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, null, null, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, BCRYPT_RESOLVE_PROVIDERS_FLAGS.CRYPT_ALL_PROVIDERS, ref pcbBuffer, ref ppBuffer);

                if (bCryptResolveProvidersStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptResolveProvidersStatus);

                if (ppBuffer->cProviders != 1U)
                    throw new SchannelServiceException(FormattableString.Invariant($"Found {ppBuffer->cProviders} providers, expected 1."));

                CRYPT_PROVIDER_REF* cryptProviderRef = ppBuffer->rgpProviders[0];
                string pszProvider = cryptProviderRef->pszProvider.ToString();
                string pszFunction = cryptProviderRef->pszFunction.ToString();
                string pszImage = cryptProviderRef->pUM->pszImage.ToString();

                HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle? phSslProvider, pszProvider);

                if (sslOpenProviderResult.Succeeded)
                {
                    HRESULT? sslEnumCipherSuitesResult = null;

                    while (sslEnumCipherSuitesResult?.Value != HRESULT.NTE_NO_MORE_ITEMS)
                    {
                        sslEnumCipherSuitesResult = PInvoke.SslEnumCipherSuites(phSslProvider, null, out ppCipherSuite, ref ppEnumState);

                        if (sslEnumCipherSuitesResult.Value.Succeeded)
                        {
                            SslProviderCipherSuiteId dwCipherSuite = ppCipherSuite->dwCipherSuite;
                            SslProviderProtocolId dwProtocol = ppCipherSuite->dwProtocol;
                            WindowsApiCipherSuiteConfiguration? windowsApiCipherSuiteConfiguration = cipherSuiteConfigurations.SingleOrDefault(q => q.Value.CipherSuite == dwCipherSuite, null);

                            if (windowsApiCipherSuiteConfiguration.HasValue)
                            {
                                windowsApiCipherSuiteConfiguration.Value.Protocols.Add(dwProtocol);

                                continue;
                            }

                            var providerProtocolIds = new List<SslProviderProtocolId> { ppCipherSuite->dwProtocol };
                            string? keyExchangeAlgorithm = null;
                            uint? minimumKeyExchangeKeyLengthBits = null;
                            uint? maximumKeyExchangeKeyLengthBits = null;
                            string? hash = null;
                            uint? hashLengthBytes = null;
                            string? serverCertificateKeyType = null;
                            SslProviderKeyTypeId? keyType = null;
                            string szExchange = ppCipherSuite->szExchange.ToString();

                            if (!string.IsNullOrWhiteSpace(szExchange))
                            {
                                keyExchangeAlgorithm = szExchange;
                                minimumKeyExchangeKeyLengthBits = ppCipherSuite->dwMinExchangeLen;
                                maximumKeyExchangeKeyLengthBits = ppCipherSuite->dwMaxExchangeLen;
                            }

                            string szHash = ppCipherSuite->szHash.ToString();

                            if (!string.IsNullOrWhiteSpace(szHash))
                            {
                                hash = szHash;
                                hashLengthBytes = ppCipherSuite->dwHashLen;
                            }

                            string szCertificate = ppCipherSuite->szCertificate.ToString();

                            if (!string.IsNullOrWhiteSpace(szCertificate))
                                serverCertificateKeyType = szCertificate;

                            SslProviderKeyTypeId dwKeyType = ppCipherSuite->dwKeyType;

                            if (dwKeyType is not 0)
                                keyType = dwKeyType;

                            var cipherSuiteConfiguration = new WindowsApiCipherSuiteConfiguration
                            {
                                Protocols = providerProtocolIds,
                                BaseCipherSuite = ppCipherSuite->dwBaseCipherSuite,
                                Certificate = serverCertificateKeyType,
                                Cipher = ppCipherSuite->szCipher.ToString(),
                                CipherBlockLength = ppCipherSuite->dwCipherBlockLen,
                                CipherLength = ppCipherSuite->dwCipherLen,
                                CipherSuite = dwCipherSuite,
                                Exchange = keyExchangeAlgorithm,
                                Hash = hash,
                                HashLength = hashLengthBytes,
                                Image = pszImage,
                                KeyType = keyType,
                                MaximumExchangeLength = maximumKeyExchangeKeyLengthBits,
                                MinimumExchangeLength = minimumKeyExchangeKeyLengthBits,
                                Provider = pszProvider,
                                CipherSuiteName = ppCipherSuite->szCipherSuite.ToString()
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

                    if (ppBuffer is not null)
                        PInvoke.BCryptFreeBuffer(ppBuffer);
                }
                else
                {
                    throw Marshal.GetExceptionForHR(sslOpenProviderResult)!;
                }
            }
            finally
            {
                if (ppCipherSuite is not null)
                    _ = PInvoke.SslFreeBuffer(ppCipherSuite);

                if (ppEnumState is not null)
                    _ = PInvoke.SslFreeBuffer(ppEnumState);
            }
        }

        cipherSuiteConfigurations.Reverse();

        return cipherSuiteConfigurations.Select(q => q.Value).ToList();
    }

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

    public void RemoveCipherSuite(string cipherSuite)
    {
        NTSTATUS status = PInvoke.BCryptRemoveContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite);

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    public void AddCipherSuite(string cipherSuite, bool top = true)
    {
        NTSTATUS status = PInvoke.BCryptAddContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite, (uint)(top ? PriorityListPosition.CRYPT_PRIORITY_TOP : PriorityListPosition.CRYPT_PRIORITY_BOTTOM));

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

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

    public List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList()
    {
        WindowsSchannelVersion windowsSchannelVersion = GetWindowsSchannelVersion();

        return windowsEllipticCurveDocumentationService.GetWindowsDocumentationEllipticCurveConfigurations(windowsSchannelVersion);
    }

    public List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList()
    {
        var list = new List<WindowsApiEllipticCurveConfiguration>();

        unsafe
        {
            var callbackFunction = new PFN_CRYPT_ENUM_OID_INFO(Callback);

            BOOL Callback(CRYPT_OID_INFO* pInfo, void* pvArg)
            {
                uint cbSize = pInfo->cbSize;
                string pszOid = pInfo->pszOID.ToString();
                string pwszName = pInfo->pwszName.ToString();
                var dwGroupId = (CRYPT_OID_GROUP_ID)pInfo->dwGroupId;
                CRYPT_OID_INFO._Anonymous_e__Union anonymous = pInfo->Anonymous;
                CRYPTOAPI_BLOB extraInfo = pInfo->ExtraInfo;
                var algId = (ALG_ID)anonymous.Algid;
                ALG_CLASS algClass = GET_ALG_CLASS(anonymous.Algid);
                ALG_TYPE algType = GET_ALG_TYPE(anonymous.Algid);
                ALG_SID algSid = GET_ALG_SID(anonymous.Algid);
                uint cbData = extraInfo.cbData;
                var flags = (CRYPT_OID_FLAG)cbData;
                uint? dwMagic = default;
                uint? keyBytesLength = default;
                uint? dwBitLength = default;

                if (extraInfo.pbData is not null)
                {
                    BCRYPT_ECCKEY_BLOB eccKeyStruct = Marshal.PtrToStructure<BCRYPT_ECCKEY_BLOB>((IntPtr)extraInfo.pbData);

                    dwMagic = eccKeyStruct.dwMagic;
                    keyBytesLength = eccKeyStruct.cbKey;
                    dwBitLength = (uint)Marshal.ReadInt32((IntPtr)extraInfo.pbData, sizeof(BCRYPT_ECCKEY_BLOB));
                }

                string? pwszCNGAlgid = Marshal.PtrToStringAuto(pInfo->pwszCNGAlgid);
                string? pwszCNGExtraAlgid = Marshal.PtrToStringAuto(pInfo->pwszCNGExtraAlgid);
                var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(cbSize, pszOid, pwszName, dwGroupId, dwMagic, algId, algClass, algType, algSid, dwBitLength, keyBytesLength, flags, pwszCNGAlgid, pwszCNGExtraAlgid);

                list.Add(windowsEllipticCurveInfo);

                return true;
            }

            void* pvArg = default;
            BOOL cryptEnumOIDInfoResult = PInvoke.CryptEnumOIDInfo((uint)CRYPT_OID_GROUP_ID.CRYPT_PUBKEY_ALG_OID_GROUP_ID, 0U, pvArg, callbackFunction);

            if (!cryptEnumOIDInfoResult)
                throw new SchannelServiceException(FormattableString.Invariant($"{nameof(GetOperatingSystemAvailableEllipticCurveList)} failed."));

            return list.Where(q => IS_SPECIAL_OID_INFO_ALGID(q.algId)).ToList();
        }
    }

    public List<string> GetOperatingSystemActiveEllipticCurveList()
    {
        using RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey(SSLConfigurationKey);
        string[]? activeEllipticCurves = (string[]?)registryKey?.GetValue(SSLCurveOrderValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

        return (activeEllipticCurves ?? Array.Empty<string>()).ToList();
    }

    public void ResetEllipticCurveListToOperatingSystemDefault()
    {
        List<WindowsDocumentationEllipticCurveConfiguration> defaultEllipticCurves = GetOperatingSystemDefaultEllipticCurveList();

        UpdateEllipticCurveOrder(defaultEllipticCurves.Select(q => q.EllipticCurveString).ToArray());
    }

    public void UpdateEllipticCurveOrder(string[] ellipticCurves)
    {
        string ellipticCurvesString = string.Join('\n', ellipticCurves);

        if (ellipticCurvesString.Length > ListMaximumCharacters)
            throw new GroupPolicyServiceException(FormattableString.Invariant($"Maximum list length exceeded ({ellipticCurvesString.Length}), the maximum is {ListMaximumCharacters}."));

        unsafe
        {
            var hKey = new SafeRegistryHandle((IntPtr)HKEY.HKEY_LOCAL_MACHINE, true);
            WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hKey, SSLConfigurationKey, 0U, null, REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS.KEY_SET_VALUE | REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

            if (regCreateKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                throw new Win32Exception((int)regCreateKeyExResult);

            fixed (char* lpData = ellipticCurvesString)
            {
                WIN32_ERROR regSetKeyValueResult = PInvoke.RegSetKeyValue(phkResult, null, SSLCurveOrderValueName, (uint)REG.REG_MULTI_SZ, lpData, (uint)(sizeof(char) * ellipticCurvesString.Length));

                if (regSetKeyValueResult is not WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regSetKeyValueResult);
            }
        }
    }

    private static WindowsSchannelVersion GetWindowsSchannelVersion()
    {
        if (Environment.OSVersion.Platform is not PlatformID.Win32NT)
            throw new SchannelServiceException(FormattableString.Invariant($"Platform is {Environment.OSVersion.Platform}, expected {nameof(PlatformID.Win32NT)}."));

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) // Windows11
            return WindowsSchannelVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348)) // WindowsServer2022
            return WindowsSchannelVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19044)) // Windows10v21H2
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19043)) // Windows10v21H1
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19042)) // Windows10v20H2
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) // Windows10v2004
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18363)) // Windows10v1909
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362)) // Windows10v1903
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) // Windows10v1809OrServer2019
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17134)) // Windows10v1803
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 16299))
            return WindowsSchannelVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 15063))
            return WindowsSchannelVersion.Windows10v1703;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 14393))
            return WindowsSchannelVersion.Windows10v1607OrServer2016;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
            return WindowsSchannelVersion.Windows10v1511;

        if (OperatingSystem.IsWindowsVersionAtLeast(10))
            return WindowsSchannelVersion.Windows10v1507;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3))
            return WindowsSchannelVersion.Windows81OrServer2012R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            return WindowsSchannelVersion.Windows8OrServer2012;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 1))
            return WindowsSchannelVersion.Windows7OrServer2008R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6))
            return WindowsSchannelVersion.WindowsVistaOrServer2008;

        throw new SchannelServiceException(FormattableString.Invariant($"Unknown Windows version {Environment.OSVersion.Version}."));
    }

    private static ALG_CLASS GET_ALG_CLASS(uint x)
    {
        return (ALG_CLASS)(x & (7 << 13));
    }

    private static ALG_TYPE GET_ALG_TYPE(uint x)
    {
        return (ALG_TYPE)(x & (15 << 9));
    }

    private static ALG_SID GET_ALG_SID(uint x)
    {
        return (ALG_SID)(x & 511);
    }

    private static bool IS_SPECIAL_OID_INFO_ALGID(ALG_ID algId)
    {
        return algId >= ALG_ID.CALG_OID_INFO_PARAMETERS;
    }
}