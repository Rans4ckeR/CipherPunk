namespace CipherPunk;

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Windows.Win32;
using Windows.Win32.Security.Cryptography;
using Windows.Win32.Foundation;
using Windows.Win32.System.Registry;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

internal sealed class EllipticCurveService : IEllipticCurveService
{
    private const string SslConfigurationKey = "SYSTEM\\CurrentControlSet\\Control\\Cryptography\\Configuration\\Local\\SSL\\00010002";
    private const string SslCurveOrderValueName = "EccCurves";
    private const ushort ListMaximumCharacters = 1023;

    private readonly IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService;
    private readonly ITlsService tlsService;

    public EllipticCurveService(IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService, ITlsService tlsService)
    {
        this.windowsEllipticCurveDocumentationService = windowsEllipticCurveDocumentationService;
        this.tlsService = tlsService;
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList()
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
                        CRYPT_OID_INFO* cryptOidInfoPointer = PInvoke.CryptFindOIDInfo((uint)CRYPT_OID_INFO_KEY.CRYPT_OID_INFO_NAME_KEY, eccCurveName, (uint)(CRYPT_OID_GROUP_FLAG.CRYPT_OID_PREFER_CNG_ALGID_FLAG | (CRYPT_OID_GROUP_FLAG)CRYPT_OID_GROUP_ID.CRYPT_PUBKEY_ALG_OID_GROUP_ID));

                        if ((nint)cryptOidInfoPointer == nint.Zero)
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
                                    uint dwVersion = bcryptEccParametersBlob.dwVersion;
                                    ECC_CURVE_TYPE_ENUM dwCurveType = bcryptEccParametersBlob.dwCurveType;
                                    ECC_CURVE_ALG_ID_ENUM dwCurveGenerationAlgId = bcryptEccParametersBlob.dwCurveGenerationAlgId;
                                    uint cbFieldLength = bcryptEccParametersBlob.cbFieldLength;
                                    uint cbSubgroupOrder = bcryptEccParametersBlob.cbSubgroupOrder;
                                    uint cbCofactor = bcryptEccParametersBlob.cbCofactor;
                                    uint cbSeed = bcryptEccParametersBlob.cbSeed;
                                }

                                // todo search strings in certutil.exe: CurveType, EccCurveFlags
                                var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(null, eccCurveNameString, null, null, null, dwMinLength, null, null, new(), null);

                                curveConfigurations.Add(windowsEllipticCurveInfo);
                            }
                        }
                        else
                        {
                            // The CRYPT_*_ALG_OID_GROUP_ID's have an Algid. The CRYPT_RDN_ATTR_OID_GROUP_ID
                            // has a dwLength. The CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
                            // CRYPT_ENHKEY_USAGE_OID_GROUP_ID, CRYPT_POLICY_OID_GROUP_ID or
                            // CRYPT_TEMPLATE_OID_GROUP_ID don't have a dwValue.
                            //
                            // CRYPT_PUBKEY_ALG_OID_GROUP_ID has the following optional ExtraInfo:
                            //  DWORD[0] - Flags. CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG can be set to
                            //             inhibit the reformatting of the signature before
                            //             CryptVerifySignature is called or after CryptSignHash
                            //             is called. CRYPT_OID_USE_PUBKEY_PARA_FOR_PKCS7_FLAG can
                            //             be set to include the public key algorithm's parameters
                            //             in the PKCS7's digestEncryptionAlgorithm's parameters.
                            //             CRYPT_OID_NO_NULL_ALGORITHM_PARA_FLAG can be set to omit
                            //             NULL parameters when encoding.
                            //
                            // For the ECC named curve public keys
                            //  DWORD[1] - BCRYPT_ECCKEY_BLOB dwMagic field value
                            //  DWORD[2] - dwBitLength. Where BCRYPT_ECCKEY_BLOB's
                            //             cbKey = dwBitLength / 8 + ((dwBitLength % 8) ? 1 : 0)
                            uint cbSize = cryptOidInfoPointer->cbSize;
                            string pszOid = cryptOidInfoPointer->pszOID.ToString();
                            string pwszName = cryptOidInfoPointer->pwszName.ToString();
                            var dwGroupId = (CRYPT_OID_GROUP_ID)cryptOidInfoPointer->dwGroupId;
                            CRYPT_OID_INFO._Anonymous_e__Union anonymous = cryptOidInfoPointer->Anonymous;
                            CRYPTOAPI_BLOB extraInfo = cryptOidInfoPointer->ExtraInfo;
                            var algId = (CALG)anonymous.Algid; // The CRYPT_*_ALG_OID_GROUP_ID's have an Algid
                            var flags = (CRYPT_OID_FLAG)extraInfo.cbData;
                            uint dwMagic;
                            BCRYPT_MAGIC bcryptMagic;
                            uint dwBitLength;

                            // if (extraInfo.pbData is not null)
                            // {
                            BCRYPT_ECCKEY_BLOB eccKeyStruct = Marshal.PtrToStructure<BCRYPT_ECCKEY_BLOB>((nint)extraInfo.pbData);

                            dwMagic = eccKeyStruct.dwMagic;
                            bcryptMagic = (BCRYPT_MAGIC)eccKeyStruct.cbKey;
                            dwBitLength = (uint)Marshal.ReadInt32((nint)extraInfo.pbData, sizeof(BCRYPT_ECCKEY_BLOB));
                            // }

                            string pwszCNGAlgid = Marshal.PtrToStringAuto(cryptOidInfoPointer->pwszCNGAlgid)!;
                            string? pwszCNGExtraAlgid = Marshal.PtrToStringAuto(cryptOidInfoPointer->pwszCNGExtraAlgid); // CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM = "CryptOIDInfoECCParameters"

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

        return curveConfigurations;
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList()
    {
        WindowsSchannelVersion windowsSchannelVersion = tlsService.GetWindowsSchannelVersion();

        return windowsEllipticCurveDocumentationService.GetWindowsDocumentationEllipticCurveConfigurations(windowsSchannelVersion);
    }

    [SupportedOSPlatform("windows")]
    public List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemActiveEllipticCurveList()
    {
        using RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey(SslConfigurationKey);
        string[] activeEllipticCurves = (string[]?)registryKey?.GetValue(SslCurveOrderValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) ?? Array.Empty<string>();
        List<WindowsApiEllipticCurveConfiguration> availableWindowsApiActiveEllipticCurveConfigurations = GetOperatingSystemAvailableEllipticCurveList();

        return availableWindowsApiActiveEllipticCurveConfigurations.Where(q => activeEllipticCurves.Contains(q.pwszName, StringComparer.OrdinalIgnoreCase)).ToList();
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void ResetEllipticCurveListToOperatingSystemDefault()
    {
        List<WindowsDocumentationEllipticCurveConfiguration> defaultEllipticCurves = GetOperatingSystemDefaultEllipticCurveList();

        UpdateEllipticCurveOrder(defaultEllipticCurves.Select(q => q.Code).ToArray());
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateEllipticCurveOrder(string[] ellipticCurves)
    {
        string ellipticCurvesString = string.Join('\n', ellipticCurves);

        if (ellipticCurvesString.Length > ListMaximumCharacters)
            throw new GroupPolicyServiceException(FormattableString.Invariant($"Maximum list length exceeded ({ellipticCurvesString.Length}), the maximum is {ListMaximumCharacters}."));

        unsafe
        {
            var hKey = new SafeRegistryHandle(HKEY.HKEY_LOCAL_MACHINE, true);
            WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hKey, SslConfigurationKey, 0U, null, REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS.KEY_SET_VALUE | REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

            if (regCreateKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                throw new Win32Exception((int)regCreateKeyExResult);

            fixed (char* lpData = ellipticCurvesString)
            {
                WIN32_ERROR regSetKeyValueResult = PInvoke.RegSetKeyValue(phkResult, null, SslCurveOrderValueName, (uint)REG_VALUE_TYPE.REG_MULTI_SZ, lpData, (uint)(sizeof(char) * ellipticCurvesString.Length));

                if (regSetKeyValueResult is not WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regSetKeyValueResult);
            }
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateEllipticCurveOrder(BCRYPT_ECC_CURVE[] ellipticCurves)
    {
        UpdateEllipticCurveOrder(ellipticCurves.Select(q => q.ToString()).ToArray());
    }
}