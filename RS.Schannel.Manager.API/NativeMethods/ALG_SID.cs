﻿namespace RS.Schannel.Manager.API;

public enum ALG_SID : uint
{
    // Generic sub-ids
    ALG_SID_ANY = 0,

    // Generic ThirdParty sub-ids
    ALG_SID_THIRDPARTY_ANY = 0,

    // Some RSA sub-ids
    ALG_SID_RSA_ANY = 0,
    ALG_SID_RSA_PKCS = 1,
    ALG_SID_RSA_MSATWORK = 2,
    ALG_SID_RSA_ENTRUST = 3,
    ALG_SID_RSA_PGP = 4,

    // Some DSS sub-ids
    ALG_SID_DSS_ANY = 0,
    ALG_SID_DSS_PKCS = 1,
    ALG_SID_DSS_DMS = 2,
    ALG_SID_ECDSA = 3,

    // Block cipher sub ids
    // DES sub_ids
    ALG_SID_DES = 1,
    ALG_SID_3DES = 3,
    ALG_SID_DESX = 4,
    ALG_SID_IDEA = 5,
    ALG_SID_CAST = 6,
    ALG_SID_SAFERSK64 = 7,
    ALG_SID_SAFERSK128 = 8,
    ALG_SID_3DES_112 = 9,
    ALG_SID_CYLINK_MEK = 12,
    ALG_SID_RC5 = 13,
    ALG_SID_AES_128 = 14,
    ALG_SID_AES_192 = 15,
    ALG_SID_AES_256 = 16,
    ALG_SID_AES = 17,

    // Fortezza sub-ids
    ALG_SID_SKIPJACK = 10,
    ALG_SID_TEK = 11,

    // RC2 sub-ids
    ALG_SID_RC2 = 2,

    // Stream cipher sub-ids
    ALG_SID_RC4 = 1,
    ALG_SID_SEAL = 2,

    // Diffie-Hellman sub-ids
    ALG_SID_DH_SANDF = 1,
    ALG_SID_DH_EPHEM = 2,
    ALG_SID_AGREED_KEY_ANY = 3,
    ALG_SID_KEA = 4,
    ALG_SID_ECDH = 5,
    ALG_SID_ECDH_EPHEM = 6,

    // Hash sub ids
    ALG_SID_MD2 = 1,
    ALG_SID_MD4 = 2,
    ALG_SID_MD5 = 3,
    ALG_SID_SHA = 4,
    ALG_SID_SHA1 = 4,
    ALG_SID_MAC = 5,
    ALG_SID_RIPEMD = 6,
    ALG_SID_RIPEMD160 = 7,
    ALG_SID_SSL3SHAMD5 = 8,
    ALG_SID_HMAC = 9,
    ALG_SID_TLS1PRF = 10,
    ALG_SID_HASH_REPLACE_OWF = 11,
    ALG_SID_SHA_256 = 12,
    ALG_SID_SHA_384 = 13,
    ALG_SID_SHA_512 = 14,

    // secure channel sub ids
    ALG_SID_SSL3_MASTER = 1,
    ALG_SID_SCHANNEL_MASTER_HASH = 2,
    ALG_SID_SCHANNEL_MAC_KEY = 3,
    ALG_SID_PCT1_MASTER = 4,
    ALG_SID_SSL2_MASTER = 5,
    ALG_SID_TLS1_MASTER = 6,
    ALG_SID_SCHANNEL_ENC_KEY = 7,

    // misc ECC sub ids
    ALG_SID_ECMQV = 1,

    // Our silly example sub-id
    ALG_SID_EXAMPLE = 80
}