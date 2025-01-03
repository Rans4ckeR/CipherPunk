﻿// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
using Windows.Win32;

namespace CipherPunk;

internal static class CngAlgorithmIdentifiers
{
    ////
    //// Common algorithm identifiers.
    ////
    public const string BCRYPT_RSA_ALGORITHM = PInvoke.BCRYPT_RSA_ALGORITHM;
    public const string BCRYPT_RSA_SIGN_ALGORITHM = PInvoke.BCRYPT_RSA_SIGN_ALGORITHM;
    public const string BCRYPT_DH_ALGORITHM = PInvoke.BCRYPT_DH_ALGORITHM;
    public const string BCRYPT_DSA_ALGORITHM = PInvoke.BCRYPT_DSA_ALGORITHM;
    public const string BCRYPT_RC2_ALGORITHM = PInvoke.BCRYPT_RC2_ALGORITHM;
    public const string BCRYPT_RC4_ALGORITHM = PInvoke.BCRYPT_RC4_ALGORITHM;
    public const string BCRYPT_AES_ALGORITHM = PInvoke.BCRYPT_AES_ALGORITHM;
    public const string BCRYPT_DES_ALGORITHM = PInvoke.BCRYPT_DES_ALGORITHM;
    public const string BCRYPT_DESX_ALGORITHM = PInvoke.BCRYPT_DESX_ALGORITHM;
    public const string BCRYPT_3DES_ALGORITHM = PInvoke.BCRYPT_3DES_ALGORITHM;
    public const string BCRYPT_3DES_112_ALGORITHM = PInvoke.BCRYPT_3DES_112_ALGORITHM;
    public const string BCRYPT_MD2_ALGORITHM = PInvoke.BCRYPT_MD2_ALGORITHM;
    public const string BCRYPT_MD4_ALGORITHM = PInvoke.BCRYPT_MD4_ALGORITHM;
    public const string BCRYPT_MD5_ALGORITHM = PInvoke.BCRYPT_MD5_ALGORITHM;
    public const string BCRYPT_SHA1_ALGORITHM = PInvoke.BCRYPT_SHA1_ALGORITHM;
    public const string BCRYPT_SHA256_ALGORITHM = PInvoke.BCRYPT_SHA256_ALGORITHM;
    public const string BCRYPT_SHA384_ALGORITHM = PInvoke.BCRYPT_SHA384_ALGORITHM;
    public const string BCRYPT_SHA512_ALGORITHM = PInvoke.BCRYPT_SHA512_ALGORITHM;
    public const string BCRYPT_AES_GMAC_ALGORITHM = PInvoke.BCRYPT_AES_GMAC_ALGORITHM;
    public const string BCRYPT_AES_CMAC_ALGORITHM = PInvoke.BCRYPT_AES_CMAC_ALGORITHM;
    public const string BCRYPT_ECDSA_P256_ALGORITHM = PInvoke.BCRYPT_ECDSA_P256_ALGORITHM;
    public const string BCRYPT_ECDSA_P384_ALGORITHM = PInvoke.BCRYPT_ECDSA_P384_ALGORITHM;
    public const string BCRYPT_ECDSA_P521_ALGORITHM = PInvoke.BCRYPT_ECDSA_P521_ALGORITHM;
    public const string BCRYPT_ECDH_P256_ALGORITHM = PInvoke.BCRYPT_ECDH_P256_ALGORITHM;
    public const string BCRYPT_ECDH_P384_ALGORITHM = PInvoke.BCRYPT_ECDH_P384_ALGORITHM;
    public const string BCRYPT_ECDH_P521_ALGORITHM = PInvoke.BCRYPT_ECDH_P521_ALGORITHM;
    public const string BCRYPT_RNG_ALGORITHM = PInvoke.BCRYPT_RNG_ALGORITHM;
    public const string BCRYPT_RNG_FIPS186_DSA_ALGORITHM = PInvoke.BCRYPT_RNG_FIPS186_DSA_ALGORITHM;
    public const string BCRYPT_RNG_DUAL_EC_ALGORITHM = PInvoke.BCRYPT_RNG_DUAL_EC_ALGORITHM;
    public const string BCRYPT_SP800108_CTR_HMAC_ALGORITHM = PInvoke.BCRYPT_SP800108_CTR_HMAC_ALGORITHM;
    public const string BCRYPT_SP80056A_CONCAT_ALGORITHM = PInvoke.BCRYPT_SP80056A_CONCAT_ALGORITHM;
    public const string BCRYPT_PBKDF2_ALGORITHM = PInvoke.BCRYPT_PBKDF2_ALGORITHM;
    public const string BCRYPT_CAPI_KDF_ALGORITHM = PInvoke.BCRYPT_CAPI_KDF_ALGORITHM;
    public const string BCRYPT_TLS1_1_KDF_ALGORITHM = PInvoke.BCRYPT_TLS1_1_KDF_ALGORITHM;
    public const string BCRYPT_TLS1_2_KDF_ALGORITHM = PInvoke.BCRYPT_TLS1_2_KDF_ALGORITHM;
    public const string BCRYPT_ECDSA_ALGORITHM = PInvoke.BCRYPT_ECDSA_ALGORITHM;
    public const string BCRYPT_ECDH_ALGORITHM = PInvoke.BCRYPT_ECDH_ALGORITHM;
    public const string BCRYPT_XTS_AES_ALGORITHM = PInvoke.BCRYPT_XTS_AES_ALGORITHM;
    public const string BCRYPT_HKDF_ALGORITHM = PInvoke.BCRYPT_HKDF_ALGORITHM;
    public const string BCRYPT_CHACHA20_POLY1305_ALGORITHM = PInvoke.BCRYPT_CHACHA20_POLY1305_ALGORITHM;
}