namespace CipherPunk;

using System.Collections.Frozen;

public readonly record struct WindowsApiEllipticCurveConfiguration(
    ushort Priority,
    string? pszOid,
    string pwszName,
    CRYPT_OID_GROUP_ID? dwGroupId,
    uint? dwMagic,
    CALG? algId,
    uint? dwBitLength,
    BCRYPT_MAGIC? bcryptMagic,
    CRYPT_OID_FLAG? flags,
    FrozenSet<string> CngAlgorithms,
    string? pwszCNGExtraAlgid);