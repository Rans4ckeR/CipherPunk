namespace RS.Schannel.Manager.API;

public readonly record struct WindowsApiEllipticCurveConfiguration(
    string pszOid,
    string pwszName,
    CRYPT_OID_GROUP_ID dwGroupId,
    uint? dwMagic,
    CALG algId,
    uint? dwBitLength,
    BCRYPT_MAGIC? bcryptMagic,
    CRYPT_OID_FLAG flags,
    List<string> CngAlgorithms,
    string? pwszCNGExtraAlgid);