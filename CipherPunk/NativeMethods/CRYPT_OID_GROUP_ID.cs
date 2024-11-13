// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
using Windows.Win32;

namespace CipherPunk;

#pragma warning disable CA1028 // Enum Storage should be Int32
[Flags]
public enum CRYPT_OID_GROUP_ID : uint
#pragma warning restore CA1028 // Enum Storage should be Int32
{
    CRYPT_ALL_OID_GROUP_ID = 0U,
    CRYPT_HASH_ALG_OID_GROUP_ID = PInvoke.CRYPT_HASH_ALG_OID_GROUP_ID,
    CRYPT_ENCRYPT_ALG_OID_GROUP_ID = PInvoke.CRYPT_ENCRYPT_ALG_OID_GROUP_ID,
    CRYPT_PUBKEY_ALG_OID_GROUP_ID = PInvoke.CRYPT_PUBKEY_ALG_OID_GROUP_ID,
    CRYPT_SIGN_ALG_OID_GROUP_ID = PInvoke.CRYPT_SIGN_ALG_OID_GROUP_ID,
    CRYPT_RDN_ATTR_OID_GROUP_ID = PInvoke.CRYPT_RDN_ATTR_OID_GROUP_ID,
    CRYPT_EXT_OR_ATTR_OID_GROUP_ID = PInvoke.CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
    CRYPT_ENHKEY_USAGE_OID_GROUP_ID = PInvoke.CRYPT_ENHKEY_USAGE_OID_GROUP_ID,
    CRYPT_POLICY_OID_GROUP_ID = PInvoke.CRYPT_POLICY_OID_GROUP_ID,
    CRYPT_TEMPLATE_OID_GROUP_ID = PInvoke.CRYPT_TEMPLATE_OID_GROUP_ID,
    CRYPT_KDF_OID_GROUP_ID = PInvoke.CRYPT_KDF_OID_GROUP_ID,
#pragma warning disable CA1069 // Enums values should not be duplicated
    CRYPT_LAST_OID_GROUP_ID = PInvoke.CRYPT_LAST_OID_GROUP_ID,
#pragma warning restore CA1069 // Enums values should not be duplicated

    CRYPT_FIRST_ALG_OID_GROUP_ID = CRYPT_HASH_ALG_OID_GROUP_ID,
    CRYPT_LAST_ALG_OID_GROUP_ID = CRYPT_SIGN_ALG_OID_GROUP_ID
}