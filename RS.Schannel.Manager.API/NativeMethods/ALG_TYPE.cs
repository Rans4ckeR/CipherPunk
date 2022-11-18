﻿namespace RS.Schannel.Manager.API;

public enum ALG_TYPE : uint
{
    ALG_TYPE_ANY = 0,
    ALG_TYPE_DSS = 1 << 9,
    ALG_TYPE_RSA = 2 << 9,
    ALG_TYPE_BLOCK = 3 << 9,
    ALG_TYPE_STREAM = 4 << 9,
    ALG_TYPE_DH = 5 << 9,
    ALG_TYPE_SECURECHANNEL = 6 << 9,
    ALG_TYPE_ECDH = 7 << 9,
    ALG_TYPE_THIRDPARTY = 8 << 9
}