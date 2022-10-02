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

    public void Test()
    {
        var curveConfigurations = new List<WindowsApiEllipticCurveConfiguration>();

        unsafe
        {
            NCryptProviderName* ppProviderList = null;
            CRYPT_PROVIDER_REFS* ppBuffer = null;

            try
            {
                HRESULT sslEnumProtocolProvidersStatus = PInvoke.SslEnumProtocolProviders(out uint pdwProviderCount, out ppProviderList);

                if (sslEnumProtocolProvidersStatus.Failed)
                    throw Marshal.GetExceptionForHR(sslEnumProtocolProvidersStatus)!;

                for (int i = 0; i < pdwProviderCount; i++)
                {
                    NCryptProviderName nCryptProviderName = Marshal.PtrToStructure<NCryptProviderName>((nint)ppProviderList + (i * sizeof(NCryptProviderName)));

                    string pszName = nCryptProviderName.pszName.ToString();
                    string pszComment = nCryptProviderName.pszComment.ToString();

                    HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle phSslProvider, pszName);

                    using (phSslProvider)
                    {
                        if (sslOpenProviderResult.Succeeded)
                        {
                        }
                        else
                        {
                            throw Marshal.GetExceptionForHR(sslOpenProviderResult)!;
                        }
                    }

                    uint pcbBuffer = 0U;
                    NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders(null, (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, null, pszName, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, 0U, ref pcbBuffer, ref ppBuffer);

                    if (bCryptResolveProvidersStatus.SeverityCode is not NTSTATUS.Severity.Success)
                        throw new Win32Exception(bCryptResolveProvidersStatus);

                    if (ppBuffer->cProviders != 1U)
                        throw new SchannelServiceException(FormattableString.Invariant($"Found {ppBuffer->cProviders} providers, expected 1."));

                    CRYPT_PROVIDER_REF* cryptProviderRef = ppBuffer->rgpProviders[0];
                    string pszProvider = cryptProviderRef->pszProvider.ToString();
                    string pszFunction = cryptProviderRef->pszFunction.ToString();
                    string pszImage = cryptProviderRef->pUM->pszImage.ToString();

                    PInvoke.BCryptFreeBuffer(ppBuffer);

                    ppBuffer = null;

                    BCRYPT_ALG_HANDLE phAlgorithm = default;
                    NTSTATUS bCryptOpenAlgorithmProviderStatus = PInvoke.BCryptOpenAlgorithmProvider(&phAlgorithm, CngAlgorithmIdentifiers.BCRYPT_ECDH_ALGORITHM, null, 0U);

                    if (bCryptOpenAlgorithmProviderStatus.SeverityCode is not NTSTATUS.Severity.Success)
                        throw new Win32Exception(bCryptOpenAlgorithmProviderStatus);

                    using var bCryptCloseAlgorithmProviderSafeHandle = new BCryptCloseAlgorithmProviderSafeHandle(phAlgorithm);
                    NTSTATUS bCryptGetPropertyStatus = PInvoke.BCryptGetProperty((BCRYPT_HANDLE)bCryptCloseAlgorithmProviderSafeHandle.DangerousGetHandle(), CngPropertyIdentifiers.BCRYPT_ECC_CURVE_NAME_LIST, null, 0, out uint length, 0);

                    if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                        throw new Win32Exception(bCryptGetPropertyStatus);

                    byte[] result = new byte[length];
                    BCRYPT_ECC_CURVE_NAMES bcryptEccCurveNames;

                    fixed (byte* p = result)
                    {
                        nint ptr = (nint)p;

                        bCryptGetPropertyStatus = PInvoke.BCryptGetProperty((BCRYPT_HANDLE)bCryptCloseAlgorithmProviderSafeHandle.DangerousGetHandle(), CngPropertyIdentifiers.BCRYPT_ECC_CURVE_NAME_LIST, (byte*)ptr, (uint)result.Length, out length, 0);

                        if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                            throw new Win32Exception(bCryptGetPropertyStatus);

                        bcryptEccCurveNames = Marshal.PtrToStructure<BCRYPT_ECC_CURVE_NAMES>(ptr);
                    }

                    for (int j = 0; j < bcryptEccCurveNames.dwEccCurveNames; j++)
                    {
                        PWSTR eccCurveName = Marshal.PtrToStructure<PWSTR>((nint)(bcryptEccCurveNames.pEccCurveNames + j));
                        string eccCurveNameString = eccCurveName.ToString();

                        nint cryptOidInfoPointer = (nint)PInvoke.CryptFindOIDInfo((uint)(CRYPT_OID_INFO_KEY.CRYPT_OID_INFO_NAME_KEY | CRYPT_OID_INFO_KEY.CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG), eccCurveName, (uint)(CRYPT_OID_GROUP_FLAG.CRYPT_OID_PREFER_CNG_ALGID_FLAG | (CRYPT_OID_GROUP_FLAG)CRYPT_OID_GROUP_ID.CRYPT_PUBKEY_ALG_OID_GROUP_ID));

                        if (cryptOidInfoPointer == nint.Zero)
                        {
                            NTSTATUS bCryptGenerateKeyPairResult = PInvoke.BCryptGenerateKeyPair(bCryptCloseAlgorithmProviderSafeHandle, out BCryptDestroyKeySafeHandle phKey, 0U, 0U);

                            using (phKey)
                            {
                                if (bCryptGenerateKeyPairResult.SeverityCode is not NTSTATUS.Severity.Success)
                                    throw new Win32Exception(bCryptGenerateKeyPairResult);

                                nint stringPointer = Marshal.StringToHGlobalUni(eccCurveNameString);

                                fixed (char* pszPropertyLocal = CngPropertyIdentifiers.BCRYPT_ECC_CURVE_NAME)
                                {
                                    NTSTATUS bCryptSetPropertyResult = PInvoke.BCryptSetProperty((BCRYPT_HANDLE)phKey.DangerousGetHandle(), pszPropertyLocal, (byte*)stringPointer, (uint)(sizeof(char) * (eccCurveName.Length + "\n".Length)), 0U);

                                    if (bCryptSetPropertyResult.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptSetPropertyResult);
                                }

                                BCRYPT_KEY_LENGTHS_STRUCT pbOutput = default;

                                bCryptGetPropertyStatus = PInvoke.BCryptGetProperty((BCRYPT_HANDLE)phKey.DangerousGetHandle(), CngPropertyIdentifiers.BCRYPT_PUBLIC_KEY_LENGTH, (byte*)&pbOutput, (uint)sizeof(BCRYPT_KEY_LENGTHS_STRUCT), out uint pcbResult, 0U);

                                if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                    throw new Win32Exception(bCryptGetPropertyStatus);

                                uint dwMinLength = pbOutput.dwMinLength;
                                uint dwMaxLength = pbOutput.dwMaxLength;
                                uint dwIncrement = pbOutput.dwIncrement;

                                bCryptGetPropertyStatus = PInvoke.BCryptGetProperty((BCRYPT_HANDLE)phKey.DangerousGetHandle(), CngPropertyIdentifiers.BCRYPT_ECC_PARAMETERS, null, 0U, out uint pcbResult1, 0U);

                                if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                    throw new Win32Exception(bCryptGetPropertyStatus);

                                byte[] result1 = new byte[pcbResult1];
                                fixed (byte* p = result1)
                                {
                                    nint ptr = (nint)p;
                                    bCryptGetPropertyStatus = PInvoke.BCryptGetProperty((BCRYPT_HANDLE)phKey.DangerousGetHandle(), CngPropertyIdentifiers.BCRYPT_ECC_PARAMETERS, (byte*)ptr, (uint)result1.Length, out uint pcbResult2, 0U);

                                    if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptGetPropertyStatus);

                                    BCRYPT_ECC_PARAMETER_HEADER bcryptEccParametersBlob = Marshal.PtrToStructure<BCRYPT_ECC_PARAMETER_HEADER>(ptr);
                                }

                                var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(null, eccCurveNameString, null, null, null, dwMinLength, null, null, new(), null);

                                curveConfigurations.Add(windowsEllipticCurveInfo);
                            }
                        }
                        else
                        {
                            CRYPT_OID_INFO pInfo = Marshal.PtrToStructure<CRYPT_OID_INFO>(cryptOidInfoPointer);
                            uint cbSize = pInfo.cbSize;
                            string pszOid = pInfo.pszOID.ToString();
                            string pwszName = pInfo.pwszName.ToString();
                            var dwGroupId = (CRYPT_OID_GROUP_ID)pInfo.dwGroupId;
                            CRYPT_OID_INFO._Anonymous_e__Union anonymous = pInfo.Anonymous;
                            CRYPTOAPI_BLOB extraInfo = pInfo.ExtraInfo;
                            var algId = (CALG)anonymous.Algid;
                            var flags = (CRYPT_OID_FLAG)extraInfo.cbData;
                            uint dwMagic;
                            BCRYPT_MAGIC bcryptMagic;
                            uint dwBitLength;

                            //if (extraInfo.pbData is not null)
                            //{
                                BCRYPT_ECCKEY_BLOB eccKeyStruct = Marshal.PtrToStructure<BCRYPT_ECCKEY_BLOB>((nint)extraInfo.pbData);

                                dwMagic = eccKeyStruct.dwMagic;
                                bcryptMagic = (BCRYPT_MAGIC)eccKeyStruct.cbKey;
                                dwBitLength = (uint)Marshal.ReadInt32((nint)extraInfo.pbData, sizeof(BCRYPT_ECCKEY_BLOB));
                            //}

                            string pwszCNGAlgid = Marshal.PtrToStringAuto(pInfo.pwszCNGAlgid)!;
                            string? pwszCNGExtraAlgid = Marshal.PtrToStringAuto(pInfo.pwszCNGExtraAlgid);

                            if (string.IsNullOrWhiteSpace(pwszCNGExtraAlgid))
                                pwszCNGExtraAlgid = null;

                            var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(pszOid, pwszName, dwGroupId, dwMagic, algId, dwBitLength, bcryptMagic, flags, new() { pwszCNGAlgid }, pwszCNGExtraAlgid);

                            curveConfigurations.Add(windowsEllipticCurveInfo);
                        }
                    }
                }
            }
            finally
            {
                if (ppProviderList is not null)
                    _ = PInvoke.SslFreeBuffer(ppProviderList);

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
            CRYPT_PROVIDER_REFS* ppBuffer = null;

            try
            {
                uint pcbBuffer = 0U;
                NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders(LocalCngSslContextName, (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, null, null, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, BCRYPT_RESOLVE_PROVIDERS_FLAGS.CRYPT_ALL_PROVIDERS, ref pcbBuffer, ref ppBuffer);

                if (bCryptResolveProvidersStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptResolveProvidersStatus);

                if (ppBuffer->cProviders != 1U)
                    throw new SchannelServiceException(FormattableString.Invariant($"Found {ppBuffer->cProviders} providers, expected 1."));

                CRYPT_PROVIDER_REF* cryptProviderRef = ppBuffer->rgpProviders[0];
                string pszProvider = cryptProviderRef->pszProvider.ToString();
                string pszFunction = cryptProviderRef->pszFunction.ToString();
                string pszImage = cryptProviderRef->pUM->pszImage.ToString();

                PInvoke.BCryptFreeBuffer(ppBuffer);

                ppBuffer = null;

                HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle phSslProvider, pszProvider);

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
                            WindowsApiCipherSuiteConfiguration? windowsApiCipherSuiteConfiguration = cipherSuiteConfigurations.SingleOrDefault(q => q!.Value.CipherSuite == dwCipherSuite, null);

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

    public void RemoveCipherSuite(SslProviderCipherSuiteId cipherSuite)
    {
        RemoveCipherSuite(cipherSuite.ToString());
    }

    public void AddCipherSuite(string cipherSuite, bool top = true)
    {
        NTSTATUS status = PInvoke.BCryptAddContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, LocalCngSslContextName, BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipherSuite, (uint)(top ? PriorityListPosition.CRYPT_PRIORITY_TOP : PriorityListPosition.CRYPT_PRIORITY_BOTTOM));

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    public void AddCipherSuite(SslProviderCipherSuiteId cipherSuite)
    {
        AddCipherSuite(cipherSuite.ToString());
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

    public void UpdateCipherSuiteOrder(SslProviderCipherSuiteId[] cipherSuites)
    {
        UpdateCipherSuiteOrder(cipherSuites.Select(q => q.ToString()).ToArray());
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
                var algId = (CALG)anonymous.Algid;
                var flags = (CRYPT_OID_FLAG)extraInfo.cbData;
                uint? dwMagic = default;
                BCRYPT_MAGIC? bcryptMagic = null;
                uint? dwBitLength = default;

                if (extraInfo.pbData is not null)
                {
                    BCRYPT_ECCKEY_BLOB eccKeyStruct = Marshal.PtrToStructure<BCRYPT_ECCKEY_BLOB>((nint)extraInfo.pbData);

                    dwMagic = eccKeyStruct.dwMagic;
                    bcryptMagic = (BCRYPT_MAGIC)eccKeyStruct.cbKey;
                    dwBitLength = (uint)Marshal.ReadInt32((nint)extraInfo.pbData, sizeof(BCRYPT_ECCKEY_BLOB));
                }

                string pwszCNGAlgid = Marshal.PtrToStringAuto(pInfo->pwszCNGAlgid)!;
                string? pwszCNGExtraAlgid = Marshal.PtrToStringAuto(pInfo->pwszCNGExtraAlgid);

                if (string.IsNullOrWhiteSpace(pwszCNGExtraAlgid))
                    pwszCNGExtraAlgid = null;

                //var x = list.SingleOrDefault(q => q.Value.pwszName.Equals(pwszName, StringComparison.OrdinalIgnoreCase));

                //if (x is not null)
                //{
                //    x.Value.CngAlgorithms.Add(pwszCNGAlgid);

                //    return true;
                //}

                var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(pszOid, pwszName, dwGroupId, dwMagic, algId, dwBitLength, bcryptMagic, flags, new() { pwszCNGAlgid }, pwszCNGExtraAlgid);

                list.Add(windowsEllipticCurveInfo);

                return true;
            }

            void* pvArg = default;

            _ = PInvoke.CryptEnumOIDInfo((uint)CRYPT_OID_GROUP_ID.CRYPT_PUBKEY_ALG_OID_GROUP_ID, 0U, pvArg, callbackFunction);

            return list.Where(q => q.CngAlgorithms.Contains(PInvoke.BCRYPT_ECDH_ALGORITHM, StringComparer.OrdinalIgnoreCase) || q.CngAlgorithms.Contains(PInvoke.BCRYPT_ECDSA_ALGORITHM, StringComparer.OrdinalIgnoreCase))
                .ToList();
        }
    }

    public List<string> GetOperatingSystemActiveEllipticCurveList()
    {
        Test();

        using RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey(SSLConfigurationKey);
        string[]? activeEllipticCurves = (string[]?)registryKey?.GetValue(SSLCurveOrderValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);

        return (activeEllipticCurves ?? Array.Empty<string>()).ToList();
    }

    public void ResetEllipticCurveListToOperatingSystemDefault()
    {
        List<WindowsDocumentationEllipticCurveConfiguration> defaultEllipticCurves = GetOperatingSystemDefaultEllipticCurveList();

        UpdateEllipticCurveOrder(defaultEllipticCurves.Select(q => q.Code).ToArray());
    }

    public void UpdateEllipticCurveOrder(string[] ellipticCurves)
    {
        string ellipticCurvesString = string.Join('\n', ellipticCurves);

        if (ellipticCurvesString.Length > ListMaximumCharacters)
            throw new GroupPolicyServiceException(FormattableString.Invariant($"Maximum list length exceeded ({ellipticCurvesString.Length}), the maximum is {ListMaximumCharacters}."));

        unsafe
        {
            var hKey = new SafeRegistryHandle(HKEY.HKEY_LOCAL_MACHINE, true);
            WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hKey, SSLConfigurationKey, 0U, null, REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS.KEY_SET_VALUE | REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

            if (regCreateKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                throw new Win32Exception((int)regCreateKeyExResult);

            fixed (char* lpData = ellipticCurvesString)
            {
                WIN32_ERROR regSetKeyValueResult = PInvoke.RegSetKeyValue(phkResult, null, SSLCurveOrderValueName, (uint)REG_VALUE_TYPE.REG_MULTI_SZ, lpData, (uint)(sizeof(char) * ellipticCurvesString.Length));

                if (regSetKeyValueResult is not WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regSetKeyValueResult);
            }
        }
    }

    public void UpdateEllipticCurveOrder(BCRYPT_ECC_CURVE[] ellipticCurves)
    {
        UpdateEllipticCurveOrder(ellipticCurves.Select(q => q.ToString()).ToArray());
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
}