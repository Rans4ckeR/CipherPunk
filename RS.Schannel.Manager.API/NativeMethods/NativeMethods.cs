﻿// ------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
// ------------------------------------------------------------------------------

namespace Windows.Win32;

using global::System.Runtime.InteropServices;
using global::System.Runtime.Versioning;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography;

internal static partial class PInvoke
{
#pragma warning disable SA1310 // Field names should not contain underscore
    public const uint STATUS_ACCESS_DENIED = 0xC0000022; // A process has requested access to an object, but has not been granted those access rights.
    public const uint NTE_NO_MORE_ITEMS = 0x8009002A;
#pragma warning restore SA1310 // Field names should not contain underscore

    [DllImport("NCrypt", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows6.0.6000")]
    public static extern unsafe HRESULT SslFreeBuffer(void* pvInput);

    [DllImport("NCrypt", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows6.0.6000")]
    public static extern unsafe HRESULT SslOpenProvider(NCRYPT_PROV_HANDLE* phSslProvider, PCWSTR pszProviderName, NCRYPT_FLAGS dwFlags);

    [DllImport("NCrypt", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    [SupportedOSPlatform("windows6.0.6000")]
    public static extern unsafe HRESULT SslEnumCipherSuites(NCRYPT_PROV_HANDLE hProvider, [Optional] NCRYPT_KEY_HANDLE hPrivateKey, NCRYPT_SSL_CIPHER_SUITE** ppCipherSuite, void** ppEnumState, NCRYPT_FLAGS dwFlags);

    public static unsafe HRESULT SslOpenProvider(out NCryptFreeObjectSafeHandle phSslProvider, string pszProviderName, NCRYPT_FLAGS dwFlags = 0U)
    {
        fixed (char* pszProviderNameLocal = pszProviderName)
        {
            NCRYPT_PROV_HANDLE phSslProviderLocal;
            HRESULT __result = PInvoke.SslOpenProvider(&phSslProviderLocal, pszProviderNameLocal, dwFlags);
            phSslProvider = new NCryptFreeObjectSafeHandle(phSslProviderLocal, ownsHandle: true);
            return __result;
        }
    }

    public static unsafe HRESULT SslEnumCipherSuites(SafeHandle hSslProvider, SafeHandle? hPrivateKey, out NCRYPT_SSL_CIPHER_SUITE* ppCipherSuite, ref void* ppEnumState, NCRYPT_FLAGS dwFlags = 0U)
    {
        bool hSslProviderAddRef = false;
        bool hPrivateKeyAddRef = false;

        try
        {
            fixed (NCRYPT_SSL_CIPHER_SUITE** ppCipherSuiteLocal = &ppCipherSuite)
            {
                fixed (void** ppEnumStateLocal = &ppEnumState)
                {
                    NCRYPT_PROV_HANDLE hSslProviderLocal;

                    if (hSslProvider is object)
                    {
                        hSslProvider.DangerousAddRef(ref hSslProviderAddRef);
                        hSslProviderLocal = (NCRYPT_PROV_HANDLE)hSslProvider.DangerousGetHandle();
                    }
                    else
                        hSslProviderLocal = default;

                    NCRYPT_KEY_HANDLE hPrivateKeyLocal;

                    if (hPrivateKey is object)
                    {
                        hPrivateKey.DangerousAddRef(ref hPrivateKeyAddRef);
                        hPrivateKeyLocal = (NCRYPT_KEY_HANDLE)hPrivateKey.DangerousGetHandle();
                    }
                    else
                        hPrivateKeyLocal = default;

                    HRESULT __result = PInvoke.SslEnumCipherSuites(hSslProviderLocal, hPrivateKeyLocal, ppCipherSuiteLocal, ppEnumStateLocal, dwFlags);
                    return __result;
                }
            }
        }
        finally
        {
            if (hSslProviderAddRef)
                hSslProvider.DangerousRelease();

            if (hPrivateKeyAddRef)
                hPrivateKey.DangerousRelease();
        }
    }
}