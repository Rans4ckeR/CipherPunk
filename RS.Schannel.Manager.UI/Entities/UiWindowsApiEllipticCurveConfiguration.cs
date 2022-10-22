namespace RS.Schannel.Manager.UI;

using RS.Schannel.Manager.API;

internal readonly record struct UiWindowsApiEllipticCurveConfiguration(
    ushort Priority,
    string? pszOid,
    string pwszName,
    CRYPT_OID_GROUP_ID? dwGroupId,
    uint? dwMagic,
    CALG? algId,
    uint? dwBitLength,
    BCRYPT_MAGIC? bcryptMagic,
    CRYPT_OID_FLAG? flags,
    string CngAlgorithms,
    string? pwszCNGExtraAlgid);