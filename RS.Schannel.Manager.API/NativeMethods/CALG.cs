﻿// ------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
// ------------------------------------------------------------------------------

#pragma warning disable CS1591,CS1573,CS0465,CS0649,CS8019,CS1570,CS1584,CS1658,CS0436,CS8981
namespace RS.Schannel.Manager.API;

using Windows.Win32;

public enum CALG : uint
{
    CALG_MD2 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_MD2,
    CALG_MD4 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_MD4,
    CALG_MD5 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_MD5,
    CALG_SHA = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_SHA,
    CALG_SHA1 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_SHA1,
    CALG_MAC = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_MAC,         // Deprecated. Don't use.
    CALG_RSA_SIGN = PInvoke.ALG_CLASS_SIGNATURE | PInvoke.ALG_TYPE_RSA | PInvoke.ALG_SID_RSA_ANY,
    CALG_DSS_SIGN = PInvoke.ALG_CLASS_SIGNATURE | PInvoke.ALG_TYPE_DSS | PInvoke.ALG_SID_DSS_ANY,
    CALG_NO_SIGN = PInvoke.ALG_CLASS_SIGNATURE | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_ANY,
    CALG_RSA_KEYX = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_RSA | PInvoke.ALG_SID_RSA_ANY,
    CALG_DES = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_DES,
    CALG_3DES_112 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_3DES_112,
    CALG_3DES = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_3DES,
    CALG_DESX = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_DESX,
    CALG_RC2 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_RC2,
    CALG_RC4 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_STREAM | PInvoke.ALG_SID_RC4,
    CALG_SEAL = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_STREAM | PInvoke.ALG_SID_SEAL,
    CALG_DH_SF = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_DH | PInvoke.ALG_SID_DH_SANDF,
    CALG_DH_EPHEM = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_DH | PInvoke.ALG_SID_DH_EPHEM,
    CALG_AGREEDKEY_ANY = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_DH | PInvoke.ALG_SID_AGREED_KEY_ANY,
    CALG_KEA_KEYX = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_DH | PInvoke.ALG_SID_KEA,
    CALG_HUGHES_MD5 = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_MD5,
    CALG_SKIPJACK = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_SKIPJACK,
    CALG_TEK = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_TEK,
    CALG_CYLINK_MEK = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_CYLINK_MEK, // Deprecated. Do not use
    CALG_SSL3_SHAMD5 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_SSL3SHAMD5,
    CALG_SSL3_MASTER = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_SSL3_MASTER,
    CALG_SCHANNEL_MASTER_HASH = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_SCHANNEL_MASTER_HASH,
    CALG_SCHANNEL_MAC_KEY = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_SCHANNEL_MAC_KEY,
    CALG_SCHANNEL_ENC_KEY = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_SCHANNEL_ENC_KEY,
    CALG_PCT1_MASTER = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_PCT1_MASTER,
    CALG_SSL2_MASTER = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_SSL2_MASTER,
    CALG_TLS1_MASTER = PInvoke.ALG_CLASS_MSG_ENCRYPT | PInvoke.ALG_TYPE_SECURECHANNEL | PInvoke.ALG_SID_TLS1_MASTER,
    CALG_RC5 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_RC5,
    CALG_HMAC = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_HMAC,
    CALG_TLS1PRF = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_TLS1PRF,
    CALG_HASH_REPLACE_OWF = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_HASH_REPLACE_OWF,
    CALG_AES_128 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_AES_128,
    CALG_AES_192 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_AES_192,
    CALG_AES_256 = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_AES_256,
    CALG_AES = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_BLOCK | PInvoke.ALG_SID_AES,
    CALG_SHA_256 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_SHA_256,
    CALG_SHA_384 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_SHA_384,
    CALG_SHA_512 = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_SHA_512,
    CALG_ECDH = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_DH | PInvoke.ALG_SID_ECDH,
    CALG_ECDH_EPHEM = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_ECDH | PInvoke.ALG_SID_ECDH_EPHEM,
    CALG_ECMQV = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_ANY | PInvoke.ALG_SID_ECMQV,
    CALG_ECDSA = PInvoke.ALG_CLASS_SIGNATURE | PInvoke.ALG_TYPE_DSS | PInvoke.ALG_SID_ECDSA,
    CALG_NULLCIPHER = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_ANY | 0,
    CALG_THIRDPARTY_KEY_EXCHANGE = PInvoke.ALG_CLASS_KEY_EXCHANGE | PInvoke.ALG_TYPE_THIRDPARTY | PInvoke.ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_SIGNATURE = PInvoke.ALG_CLASS_SIGNATURE | PInvoke.ALG_TYPE_THIRDPARTY | PInvoke.ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_CIPHER = PInvoke.ALG_CLASS_DATA_ENCRYPT | PInvoke.ALG_TYPE_THIRDPARTY | PInvoke.ALG_SID_THIRDPARTY_ANY,
    CALG_THIRDPARTY_HASH = PInvoke.ALG_CLASS_HASH | PInvoke.ALG_TYPE_THIRDPARTY | PInvoke.ALG_SID_THIRDPARTY_ANY,
    CALG_OID_INFO_CNG_ONLY = PInvoke.CALG_OID_INFO_CNG_ONLY, // Algorithm is only implemented in CNG.
    CALG_OID_INFO_PARAMETERS = PInvoke.CALG_OID_INFO_PARAMETERS // Algorithm is defined in the encoded parameters. Only supported using CNG.
}