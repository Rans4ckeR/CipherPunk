namespace RS.Schannel.Manager.API;

using System.ComponentModel;
using System.Runtime.InteropServices;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;
using RS.Schannel.Manager.CipherSuiteInfoApi;

internal sealed class SchannelService : ISchannelService
{
    private readonly ICipherSuiteInfoApiService cipherSuiteInfoApiService;

    public SchannelService(ICipherSuiteInfoApiService cipherSuiteInfoApiService)
    {
        this.cipherSuiteInfoApiService = cipherSuiteInfoApiService;
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

    public List<WindowsCipherSuiteConfiguration> GetOperatingSystemDefaultCipherSuiteList()
    {
        WindowsCipherSuiteListVersion windowsCipherSuiteListVersion = GetWindowsCipherSuiteListVersion();

        return Constants.WindowsCipherSuiteConfigurations[windowsCipherSuiteListVersion];
    }

    public async Task<List<CipherSuiteConfiguration>> GetOperatingSystemActiveCipherSuiteListAsync(bool includeOnlineInfo = true, CancellationToken cancellationToken = default)
    {
        uint pcbBuffer = 0U;
        var cipherSuiteConfigurations = new List<CipherSuiteConfiguration>();
        string[] contexts = GetLocalCngConfigurationContextIdentifiers();

        if (!contexts.Contains("SSL"))
            throw new Exception();

        unsafe
        {
            CRYPT_CONTEXT_FUNCTIONS* ppBuffer = null;
            NCRYPT_SSL_CIPHER_SUITE* ppCipherSuite = null;
            void* ppEnumState = null;

            try
            {
                NTSTATUS bCryptEnumContextFunctionsStatus = PInvoke.BCryptEnumContextFunctions(BCRYPT_TABLE.CRYPT_LOCAL, "SSL", BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, ref pcbBuffer, ref ppBuffer);

                if (bCryptEnumContextFunctionsStatus.SeverityCode is not NTSTATUS.Severity.Success)
                    throw new Win32Exception(bCryptEnumContextFunctionsStatus);

                for (int i = 0; i < ppBuffer->cFunctions; i++)
                {
                    string rgpszFunction = ppBuffer->rgpszFunctions[i].ToString();
                    var cipherSuiteConfiguration = new CipherSuiteConfiguration();

                    cipherSuiteConfigurations.Add(cipherSuiteConfiguration);

                    uint pcbBuffer1 = 0U;
                    CRYPT_PROVIDER_REFS* ppBuffer1 = null;
                    NTSTATUS bCryptResolveProvidersStatus = PInvoke.BCryptResolveProviders("SSL", (uint)BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, rgpszFunction, null, BCRYPT_QUERY_PROVIDER_MODE.CRYPT_UM, BCRYPT_RESOLVE_PROVIDERS_FLAGS.CRYPT_ALL_PROVIDERS, ref pcbBuffer1, ref ppBuffer1);

                    if (bCryptResolveProvidersStatus.SeverityCode is not NTSTATUS.Severity.Success)
                        throw new Win32Exception(bCryptResolveProvidersStatus);

                    if (ppBuffer1->cProviders != 1U)
                        throw new Exception();

                    CRYPT_PROVIDER_REF* cryptProviderRef = ppBuffer1->rgpProviders[0];
                    string pszProvider = cryptProviderRef->pszProvider.ToString();
                    string pszFunction = cryptProviderRef->pszFunction.ToString();
                    string pszImage = cryptProviderRef->pUM->pszImage.ToString();

                    cipherSuiteConfiguration.Provider = pszProvider;
                    cipherSuiteConfiguration.Function = pszFunction;
                    cipherSuiteConfiguration.Image = pszImage;

                    HRESULT sslOpenProviderResult = PInvoke.SslOpenProvider(out NCryptFreeObjectSafeHandle? phSslProvider, pszProvider);

                    if (sslOpenProviderResult.Succeeded)
                    {
                        var sslEnumCipherSuitesResult = new HRESULT(0);

                        while (sslEnumCipherSuitesResult.Value is not unchecked((int)PInvoke.NTE_NO_MORE_ITEMS))
                        {
                            sslEnumCipherSuitesResult = PInvoke.SslEnumCipherSuites(phSslProvider, null, out ppCipherSuite, ref ppEnumState);

                            if (sslEnumCipherSuitesResult.Succeeded)
                            {
                                if (ppCipherSuite->szCipherSuite.ToString().Equals(rgpszFunction, StringComparison.OrdinalIgnoreCase))
                                {
                                    cipherSuiteConfiguration.Protocols.Add(*(uint*)ppCipherSuite);

                                    if (string.IsNullOrEmpty(cipherSuiteConfiguration.Cipher))
                                    {
                                        cipherSuiteConfiguration.Cipher = ppCipherSuite->szCipher.ToString();
                                        cipherSuiteConfiguration.CipherSuite = ppCipherSuite->dwCipherSuite;
                                        cipherSuiteConfiguration.BaseCipherSuite = ppCipherSuite->dwBaseCipherSuite;
                                    }

                                    if (string.IsNullOrEmpty(cipherSuiteConfiguration.Exchange))
                                    {
                                        cipherSuiteConfiguration.Exchange = ppCipherSuite->szExchange.ToString();
                                        cipherSuiteConfiguration.MinimumExchangeLength = ppCipherSuite->dwMinExchangeLen;
                                        cipherSuiteConfiguration.MaximumExchangeLength = ppCipherSuite->dwMaxExchangeLen;
                                    }

                                    if (string.IsNullOrEmpty(cipherSuiteConfiguration.Hash))
                                    {
                                        cipherSuiteConfiguration.HashLength = ppCipherSuite->dwHashLen;
                                        cipherSuiteConfiguration.Hash = ppCipherSuite->szHash.ToString();
                                    }

                                    cipherSuiteConfiguration.CipherBlockLength = ppCipherSuite->dwCipherBlockLen;
                                    cipherSuiteConfiguration.CipherLength = ppCipherSuite->dwCipherLen;

                                    if (string.IsNullOrEmpty(cipherSuiteConfiguration.Certificate))
                                    {
                                        cipherSuiteConfiguration.Certificate = ppCipherSuite->szCertificate.ToString();
                                        cipherSuiteConfiguration.KeyType = ppCipherSuite->dwKeyType;
                                    }
                                }

                                if (ppCipherSuite is not null)
                                {
                                    HRESULT sslFreeBufferResult = PInvoke.SslFreeBuffer(ppCipherSuite);

                                    ppCipherSuite = null;

                                    if (sslFreeBufferResult.Failed)
                                        throw Marshal.GetExceptionForHR(sslFreeBufferResult)!;
                                }

                            }
                            else if (sslEnumCipherSuitesResult.Value != unchecked((int)PInvoke.NTE_NO_MORE_ITEMS))
                            {
                                throw Marshal.GetExceptionForHR(sslEnumCipherSuitesResult)!;
                            }
                        }

                        if (ppEnumState is not null)
                        {
                            HRESULT sslFreeBufferResult = PInvoke.SslFreeBuffer(ppEnumState);

                            ppEnumState = null;

                            if (sslFreeBufferResult.Failed)
                                throw Marshal.GetExceptionForHR(sslFreeBufferResult)!;
                        }

                        if (ppBuffer1 is not null)
                            PInvoke.BCryptFreeBuffer(ppBuffer1);
                    }
                    else
                    {
                        throw Marshal.GetExceptionForHR(sslOpenProviderResult)!;
                    }
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

        if (includeOnlineInfo)
        {
            foreach (CipherSuiteConfiguration cipherSuiteConfiguration in cipherSuiteConfigurations)
            {
                cipherSuiteConfiguration.OnlineInfo = await cipherSuiteInfoApiService.GetCipherSuite(cipherSuiteConfiguration.Function, cancellationToken);
            }
        }

        return cipherSuiteConfigurations;
    }

    public void ResetList()
    {
        //List<CipherSuiteConfiguration> ciphers = GetOperatingSystemActiveCipherSuiteList();

        //foreach (string cipher in ciphers.Select(q => q.Name))
        //{
        //    RemoveCipher(cipher);
        //}
    }

    public void RemoveCipher(string cipher)
    {
        NTSTATUS status = PInvoke.BCryptRemoveContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, "SSL", BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipher);

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    public void AddCipher(string cipher, bool top = true)
    {
        NTSTATUS status = PInvoke.BCryptAddContextFunction(BCRYPT_TABLE.CRYPT_LOCAL, "SSL", BCRYPT_INTERFACE.NCRYPT_SCHANNEL_INTERFACE, cipher, (uint)(top ? PriorityListPosition.CRYPT_PRIORITY_TOP : PriorityListPosition.CRYPT_PRIORITY_BOTTOM));

        if (status.SeverityCode is not NTSTATUS.Severity.Success)
            throw new Win32Exception(status);
    }

    private static WindowsCipherSuiteListVersion GetWindowsCipherSuiteListVersion()
    {
        if (Environment.OSVersion.Platform is not PlatformID.Win32NT)
            throw new Exception();

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000)) // Windows11
            return WindowsCipherSuiteListVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 20348)) // WindowsServer2022
            return WindowsCipherSuiteListVersion.Windows11OrServer2022;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19044)) // Windows10v21H2
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19043)) // Windows10v21H1
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19042)) // Windows10v20H2
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041)) // Windows10v2004
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18363)) // Windows10v1909
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 18362)) // Windows10v1903
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17763)) // Windows10v1809OrServer2019
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 17134)) // Windows10v1803
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 16299))
            return WindowsCipherSuiteListVersion.Windows10v1709;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 15063))
            return WindowsCipherSuiteListVersion.Windows10v1703;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 14393))
            return WindowsCipherSuiteListVersion.Windows10v1607OrServer2016;

        if (OperatingSystem.IsWindowsVersionAtLeast(10, 0, 10586))
            return WindowsCipherSuiteListVersion.Windows10v1511;

        if (OperatingSystem.IsWindowsVersionAtLeast(10))
            return WindowsCipherSuiteListVersion.Windows10v1507;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 3))
            return WindowsCipherSuiteListVersion.Windows81OrServer2012R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 2))
            return WindowsCipherSuiteListVersion.Windows8OrServer2012;

        if (OperatingSystem.IsWindowsVersionAtLeast(6, 1))
            return WindowsCipherSuiteListVersion.Windows7OrServer2008R2;

        if (OperatingSystem.IsWindowsVersionAtLeast(6))
            return WindowsCipherSuiteListVersion.WindowsVistaOrServer2008;

        throw new Exception();
    }
}