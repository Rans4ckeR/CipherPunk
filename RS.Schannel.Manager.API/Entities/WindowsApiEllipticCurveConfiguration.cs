namespace RS.Schannel.Manager.API;

public readonly record struct WindowsApiEllipticCurveConfiguration(uint cbSize, string pszOid, string pwszName, CRYPT_OID_GROUP_ID dwGroupId, uint? dwMagic, ALG_ID algId, ALG_CLASS algClass, ALG_TYPE algType, ALG_SID algSid, uint? dwBitLength, uint? keyBytesLength, CRYPT_OID_FLAG flags, string? pwszCNGAlgid, string? pwszCNGExtraAlgid);