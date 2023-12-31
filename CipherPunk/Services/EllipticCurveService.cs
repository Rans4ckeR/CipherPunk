namespace CipherPunk;

using System.ComponentModel;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;
using Windows.Win32.System.Registry;

internal sealed class EllipticCurveService(
    IWindowsEllipticCurveDocumentationService windowsEllipticCurveDocumentationService, ITlsService tlsService)
    : IEllipticCurveService
{
    private const string NcryptSchannelInterfaceSslKey = @"SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002";
    private const string CurveOrderValueName = "EccCurves";
    private const ushort ListMaximumCharacters = 1023;

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemAvailableEllipticCurveList()
    {
        var curveConfigurations = new List<WindowsApiEllipticCurveConfiguration>();

        unsafe
        {
            NCryptProviderName* ppProviderList = null;

            try
            {
                HRESULT sslEnumProtocolProvidersStatus = PInvoke.SslEnumProtocolProviders(out uint pdwProviderCount, out ppProviderList);

                if (sslEnumProtocolProvidersStatus.Failed)
                    throw new Win32Exception(sslEnumProtocolProvidersStatus);

                for (uint i = uint.MinValue; i < pdwProviderCount; i++)
                {
                    NCryptProviderName nCryptProviderName = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<NCryptProviderName>(ppProviderList + (i * sizeof(NCryptProviderName))), 1)[0];
                    string? pszName = nCryptProviderName.pszName.ToString();
                    string? pszComment = nCryptProviderName.pszComment.ToString();
                    HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle phSslProvider, pszName);

                    phSslProvider.Dispose();

                    if (sslOpenProviderResult.Failed)
                        throw new Win32Exception(sslOpenProviderResult);

                    uint pcbBuffer = 0U;
                    CRYPT_PROVIDER_REFS* ppBuffer = null;

                    try
                    {
                        NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders(null, (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, null, pszName, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, 0U, ref pcbBuffer, &ppBuffer);

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
                    }
                    finally
                    {
                        PInvoke.BCryptFreeBuffer(ppBuffer);
                    }

                    BCRYPT_ALG_HANDLE phAlgorithm = default;

                    try
                    {
                        NTSTATUS bCryptOpenAlgorithmProviderStatus = PInvoke.BCryptOpenAlgorithmProvider(&phAlgorithm, CngAlgorithmIdentifiers.BCRYPT_ECDH_ALGORITHM, null, 0U);

                        if (bCryptOpenAlgorithmProviderStatus.SeverityCode is not NTSTATUS.Severity.Success)
                            throw new Win32Exception(bCryptOpenAlgorithmProviderStatus);

                        var hObject = new BCRYPT_HANDLE(phAlgorithm);
                        NTSTATUS bCryptGetPropertyStatus = PInvoke.BCryptGetProperty(hObject, CngPropertyIdentifiers.BCRYPT_ECC_CURVE_NAME_LIST, null, out uint pcbResult, 0U);

                        if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                            throw new Win32Exception(bCryptGetPropertyStatus);

                        Span<byte> bcryptEccCurveNamesSpan = new byte[pcbResult];

                        bCryptGetPropertyStatus = PInvoke.BCryptGetProperty(hObject, CngPropertyIdentifiers.BCRYPT_ECC_CURVE_NAME_LIST, bcryptEccCurveNamesSpan, out _, 0U);

                        if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                            throw new Win32Exception(bCryptGetPropertyStatus);

                        BCRYPT_ECC_CURVE_NAMES bcryptEccCurveNames = MemoryMarshal.AsRef<BCRYPT_ECC_CURVE_NAMES>(bcryptEccCurveNamesSpan);
                        ReadOnlySpan<PWSTR> eccCurveNames = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<PWSTR>(bcryptEccCurveNames.pEccCurveNames), (int)bcryptEccCurveNames.dwEccCurveNames);

                        foreach (PWSTR eccCurveName in eccCurveNames)
                        {
                            string? eccCurveNameString = eccCurveName.ToString();
                            CRYPT_OID_INFO* cryptOidInfoPointer = PInvoke.CryptFindOIDInfo((uint)CRYPT_OID_INFO_KEY.CRYPT_OID_INFO_NAME_KEY, eccCurveName, (uint)(CRYPT_OID_GROUP_FLAG.CRYPT_OID_PREFER_CNG_ALGID_FLAG | (CRYPT_OID_GROUP_FLAG)CRYPT_OID_GROUP_ID.CRYPT_PUBKEY_ALG_OID_GROUP_ID));

                            if (cryptOidInfoPointer is null)
                            {
                                NTSTATUS bCryptGenerateKeyPairResult = PInvoke.BCryptGenerateKeyPair(phAlgorithm, out BCryptDestroyKeySafeHandle phKey, 0U, 0U);

                                using (phKey)
                                {
                                    if (bCryptGenerateKeyPairResult.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptGenerateKeyPairResult);

                                    nint stringPointer = Marshal.StringToHGlobalUni(eccCurveNameString);
                                    var hObjectKey = new BCRYPT_HANDLE((void*)phKey.DangerousGetHandle());
                                    NTSTATUS bCryptSetPropertyResult;

                                    try
                                    {
                                        Span<byte> pbInput = new(stringPointer.ToPointer(), sizeof(char) * (eccCurveName.Length + "\n".Length));

                                        bCryptSetPropertyResult = PInvoke.BCryptSetProperty(hObjectKey, CngPropertyIdentifiers.BCRYPT_ECC_CURVE_NAME, pbInput, 0U);
                                    }
                                    finally
                                    {
                                        Marshal.FreeHGlobal(stringPointer);
                                    }

                                    if (bCryptSetPropertyResult.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptSetPropertyResult);

                                    bCryptGetPropertyStatus = PInvoke.BCryptGetProperty(hObjectKey, CngPropertyIdentifiers.BCRYPT_PUBLIC_KEY_LENGTH, null, out pcbResult, 0U);

                                    if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptGetPropertyStatus);

                                    Span<byte> bcryptKeyLengthsStructSpan = new byte[pcbResult];

                                    bCryptGetPropertyStatus = PInvoke.BCryptGetProperty(hObjectKey, CngPropertyIdentifiers.BCRYPT_PUBLIC_KEY_LENGTH, bcryptKeyLengthsStructSpan, out uint _, 0U);

                                    if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptGetPropertyStatus);

                                    uint dwBitLength = BitConverter.ToUInt32(bcryptKeyLengthsStructSpan);

                                    bCryptGetPropertyStatus = PInvoke.BCryptGetProperty(hObjectKey, CngPropertyIdentifiers.BCRYPT_ECC_PARAMETERS, null, out pcbResult, 0U);

                                    if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptGetPropertyStatus);

                                    Span<byte> bcryptEccParametersBlobSpan = new byte[pcbResult];

                                    bCryptGetPropertyStatus = PInvoke.BCryptGetProperty(hObjectKey, CngPropertyIdentifiers.BCRYPT_ECC_PARAMETERS, bcryptEccParametersBlobSpan, out uint _, 0U);

                                    if (bCryptGetPropertyStatus.SeverityCode is not NTSTATUS.Severity.Success)
                                        throw new Win32Exception(bCryptGetPropertyStatus);

                                    BCRYPT_ECC_PARAMETER_HEADER bcryptEccParametersBlob = MemoryMarshal.AsRef<BCRYPT_ECC_PARAMETER_HEADER>(bcryptEccParametersBlobSpan);
                                    uint dwVersion = bcryptEccParametersBlob.dwVersion;
                                    ECC_CURVE_TYPE_ENUM dwCurveType = bcryptEccParametersBlob.dwCurveType;
                                    ECC_CURVE_ALG_ID_ENUM dwCurveGenerationAlgId = bcryptEccParametersBlob.dwCurveGenerationAlgId;
                                    uint cbFieldLength = bcryptEccParametersBlob.cbFieldLength;
                                    uint cbSubgroupOrder = bcryptEccParametersBlob.cbSubgroupOrder;
                                    uint cbCofactor = bcryptEccParametersBlob.cbCofactor;
                                    uint cbSeed = bcryptEccParametersBlob.cbSeed;
                                    BigInteger prime;
                                    BigInteger a;
                                    BigInteger b;
                                    BigInteger gx;
                                    BigInteger gy;
                                    BigInteger subgroupOrder;
                                    BigInteger cofactor;
                                    BigInteger seed;

                                    fixed (byte* spanPointer = bcryptEccParametersBlobSpan)
                                    {
                                        ReadOnlySpan<byte> parameters = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<byte>(spanPointer + sizeof(BCRYPT_ECC_PARAMETER_HEADER)), (int)((cbFieldLength * 5) + cbSubgroupOrder + cbCofactor + cbSeed));

                                        prime = new(parameters[..(int)cbFieldLength], true, true);
                                        a = new(parameters[(int)cbFieldLength..(int)(cbFieldLength * 2)], true, true);
                                        b = new(parameters[(int)(cbFieldLength * 2)..(int)(cbFieldLength * 3)], true, true);
                                        gx = new(parameters[(int)(cbFieldLength * 3)..(int)(cbFieldLength * 4)], true, true);
                                        gy = new(parameters[(int)(cbFieldLength * 4)..(int)(cbFieldLength * 5)], true, true);
                                        subgroupOrder = new(parameters[(int)(cbFieldLength * 5)..(int)((cbFieldLength * 5) + cbSubgroupOrder)], true, true);
                                        cofactor = new(parameters[(int)((cbFieldLength * 5) + cbSubgroupOrder)..(int)((cbFieldLength * 5) + cbSubgroupOrder + cbCofactor)], true, true);
                                        seed = new(parameters[(int)((cbFieldLength * 5) + cbSubgroupOrder + cbCofactor)..(int)((cbFieldLength * 5) + cbSubgroupOrder + cbCofactor + cbSeed)], true, true);
                                    }

                                    // todo search strings in certutil.exe: CurveType, EccCurveFlags
                                    var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(null, eccCurveNameString, null, null, null, dwBitLength, null, null, [], null);

                                    curveConfigurations.Add(windowsEllipticCurveInfo);
                                }
                            }
                            else
                            {
                                //// The CRYPT_*_ALG_OID_GROUP_ID's have an Algid. The CRYPT_RDN_ATTR_OID_GROUP_ID
                                //// has a dwLength. The CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
                                //// CRYPT_ENHKEY_USAGE_OID_GROUP_ID, CRYPT_POLICY_OID_GROUP_ID or
                                //// CRYPT_TEMPLATE_OID_GROUP_ID don't have a dwValue.
                                ////
                                //// CRYPT_PUBKEY_ALG_OID_GROUP_ID has the following optional ExtraInfo:
                                ////  DWORD[0] - Flags. CRYPT_OID_INHIBIT_SIGNATURE_FORMAT_FLAG can be set to
                                ////             inhibit the reformatting of the signature before
                                ////             CryptVerifySignature is called or after CryptSignHash
                                ////             is called. CRYPT_OID_USE_PUBKEY_PARA_FOR_PKCS7_FLAG can
                                ////             be set to include the public key algorithm's parameters
                                ////             in the PKCS7's digestEncryptionAlgorithm's parameters.
                                ////
                                ////             NULL parameters when encoding.
                                ////
                                //// For the ECC named curve public keys
                                ////  DWORD[1] - BCRYPT_ECCKEY_BLOB dwMagic field value
                                ////  DWORD[2] - dwBitLength. Where BCRYPT_ECCKEY_BLOB's
                                ////             cbKey = dwBitLength / 8 + ((dwBitLength % 8) ? 1 : 0)
                                CRYPT_OID_INFO cryptOidInfo = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<CRYPT_OID_INFO>(cryptOidInfoPointer), 1)[0];
                                uint cbSize = cryptOidInfo.cbSize;
                                string? pszOid = cryptOidInfo.pszOID.ToString();
                                string? pwszName = cryptOidInfo.pwszName.ToString();
                                var dwGroupId = (CRYPT_OID_GROUP_ID)cryptOidInfo.dwGroupId;
                                CRYPT_OID_INFO._Anonymous_e__Union anonymous = cryptOidInfo.Anonymous;
                                CRYPT_INTEGER_BLOB extraInfo = cryptOidInfo.ExtraInfo;
                                var algId = (CALG)anonymous.Algid; // The CRYPT_*_ALG_OID_GROUP_ID's have an Algid
                                var flags = (CRYPT_OID_FLAG)extraInfo.cbData;

                                //// if (extraInfo.pbData is not null)
                                //// {
                                BCRYPT_ECCKEY_BLOB eccKeyStruct = MemoryMarshal.CreateReadOnlySpan(ref Unsafe.AsRef<BCRYPT_ECCKEY_BLOB>(extraInfo.pbData), 1)[0];
                                uint dwMagic = eccKeyStruct.dwMagic;
                                var bcryptMagic = (BCRYPT_MAGIC)eccKeyStruct.cbKey;
                                uint dwBitLength = (uint)Marshal.ReadInt32((nint)extraInfo.pbData, sizeof(BCRYPT_ECCKEY_BLOB));
                                //// }

                                string? pwszCNGAlgid = Marshal.PtrToStringAuto(cryptOidInfo.pwszCNGAlgid);
                                string? pwszCNGExtraAlgid = Marshal.PtrToStringAuto(cryptOidInfo.pwszCNGExtraAlgid); // CRYPT_OID_INFO_ECC_PARAMETERS_ALGORITHM = "CryptOIDInfoECCParameters"

                                if (string.IsNullOrWhiteSpace(pwszCNGExtraAlgid))
                                    pwszCNGExtraAlgid = null;

                                var windowsEllipticCurveInfo = new WindowsApiEllipticCurveConfiguration(pszOid, pwszName, dwGroupId, dwMagic, algId, dwBitLength, bcryptMagic, flags, [pwszCNGAlgid!], pwszCNGExtraAlgid);

                                curveConfigurations.Add(windowsEllipticCurveInfo);
                            }
                        }
                    }
                    finally
                    {
                        _ = PInvoke.BCryptCloseAlgorithmProvider(phAlgorithm, 0U);
                    }
                }
            }
            finally
            {
                if (ppProviderList is not null)
                    _ = PInvoke.SslFreeBuffer(ppProviderList);
            }
        }

        return curveConfigurations;
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsDocumentationEllipticCurveConfiguration> GetOperatingSystemDefaultEllipticCurveList()
    {
        WindowsVersion windowsVersion = tlsService.GetWindowsVersion();

        return windowsEllipticCurveDocumentationService.GetWindowsDocumentationEllipticCurveConfigurations(windowsVersion);
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public List<WindowsApiEllipticCurveConfiguration> GetOperatingSystemActiveEllipticCurveList()
    {
        using RegistryKey? registryKey = Registry.LocalMachine.OpenSubKey(NcryptSchannelInterfaceSslKey);
        string[] activeEllipticCurves = (string[]?)registryKey?.GetValue(CurveOrderValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames) ?? [];
        List<WindowsApiEllipticCurveConfiguration> availableWindowsApiActiveEllipticCurveConfigurations = GetOperatingSystemAvailableEllipticCurveList();

        return availableWindowsApiActiveEllipticCurveConfigurations.Where(q => activeEllipticCurves.Contains(q.pwszName, StringComparer.OrdinalIgnoreCase)).ToList();
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void ResetEllipticCurveListToOperatingSystemDefault()
    {
        IEnumerable<WindowsDocumentationEllipticCurveConfiguration> defaultEllipticCurves = GetOperatingSystemDefaultEllipticCurveList().Where(q => q.EnabledByDefault);

        UpdateEllipticCurveOrder(defaultEllipticCurves.Select(q => q.Name).ToArray());
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateEllipticCurveOrder(string[] ellipticCurves)
    {
        string ellipticCurvesString = FormattableString.Invariant($"{string.Join('\0', ellipticCurves)}\0\0");

        if (ellipticCurvesString.Length > ListMaximumCharacters)
            throw new GroupPolicyServiceException(FormattableString.Invariant($"Maximum list length exceeded ({ellipticCurvesString.Length}), the maximum is {ListMaximumCharacters}."));

        using var hKey = new SafeRegistryHandle(HKEY.HKEY_LOCAL_MACHINE, true);

        unsafe
        {
            WIN32_ERROR regCreateKeyExResult = PInvoke.RegCreateKeyEx(hKey, NcryptSchannelInterfaceSslKey, null, REG_OPEN_CREATE_OPTIONS.REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS.KEY_SET_VALUE | REG_SAM_FLAGS.KEY_QUERY_VALUE, null, out SafeRegistryHandle phkResult, null);

            using (phkResult)
            {
                if (regCreateKeyExResult is not WIN32_ERROR.ERROR_SUCCESS)
                    throw new Win32Exception((int)regCreateKeyExResult);

                fixed (char* lpData = ellipticCurvesString)
                {
                    WIN32_ERROR regSetKeyValueResult = PInvoke.RegSetKeyValue(phkResult, null, CurveOrderValueName, (uint)REG_VALUE_TYPE.REG_MULTI_SZ, lpData, (uint)(sizeof(char) * ellipticCurvesString.Length));

                    if (regSetKeyValueResult is not WIN32_ERROR.ERROR_SUCCESS)
                        throw new Win32Exception((int)regSetKeyValueResult);
                }
            }
        }
    }

    [SupportedOSPlatform("windows6.0.6000")]
    public void UpdateEllipticCurveOrder(BCRYPT_ECC_CURVE[] ellipticCurves) => UpdateEllipticCurveOrder(ellipticCurves.Select(q => q.ToString()).ToArray());
}