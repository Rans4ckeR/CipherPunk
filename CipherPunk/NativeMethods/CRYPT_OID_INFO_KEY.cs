// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
using Windows.Win32;

namespace CipherPunk;

[Flags]
internal enum CRYPT_OID_INFO_KEY : uint
{
    CRYPT_OID_INFO_OID_KEY = PInvoke.CRYPT_OID_INFO_OID_KEY,
    CRYPT_OID_INFO_NAME_KEY = PInvoke.CRYPT_OID_INFO_NAME_KEY,
    CRYPT_OID_INFO_ALGID_KEY = PInvoke.CRYPT_OID_INFO_ALGID_KEY,
    CRYPT_OID_INFO_SIGN_KEY = PInvoke.CRYPT_OID_INFO_SIGN_KEY,
    CRYPT_OID_INFO_CNG_ALGID_KEY = PInvoke.CRYPT_OID_INFO_CNG_ALGID_KEY,
    CRYPT_OID_INFO_CNG_SIGN_KEY = PInvoke.CRYPT_OID_INFO_CNG_SIGN_KEY,

    // Set the following in the above dwKeyType parameter to restrict public keys
    // valid for signing or encrypting
    // certenrolld_begin -- CRYPT_*_KEY_FLAG
    CRYPT_OID_INFO_OID_KEY_FLAGS_MASK = PInvoke.CRYPT_OID_INFO_OID_KEY_FLAGS_MASK,
    CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = PInvoke.CRYPT_OID_PUBKEY_SIGN_ONLY_FLAG,
    CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = PInvoke.CRYPT_OID_PUBKEY_ENCRYPT_ONLY_FLAG
}