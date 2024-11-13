// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
using Windows.Win32;

namespace CipherPunk;

[Flags]
internal enum CRYPT_OID_GROUP_FLAG : uint
{
    // The following flag can be set in above dwGroupId parameter to disable
    // searching the directory server
    CRYPT_OID_DISABLE_SEARCH_DS_FLAG = PInvoke.CRYPT_OID_DISABLE_SEARCH_DS_FLAG,

    // The following flag can be set in above dwGroupId parameter to search
    // through CRYPT_OID_INFO records. If there are multiple records that meet
    // the search criteria, the first record with defined pwszCNGAlgid would be
    // returned. If none of the records (meeting the search criteria) have
    // pwszCNGAlgid defined, first record (meeting the search criteria) would be
    // returned.
    CRYPT_OID_PREFER_CNG_ALGID_FLAG = PInvoke.CRYPT_OID_PREFER_CNG_ALGID_FLAG
}