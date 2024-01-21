// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
namespace CipherPunk;

#pragma warning disable CA1028 // Enum Storage should be Int32
public enum SslCipherSuite : uint
#pragma warning restore CA1028 // Enum Storage should be Int32
{
    SSL_CK_RC4_128_WITH_MD5 = 0x010080,
    SSL_CK_RC4_128_EXPORT40_WITH_MD5 = 0x020080,
    SSL_CK_RC2_128_CBC_WITH_MD5 = 0x030080,
    SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080,
    SSL_CK_IDEA_128_CBC_WITH_MD5 = 0x050080,
    SSL_CK_DES_64_CBC_WITH_MD5 = 0x060040,
    SSL_CK_DES_64_CBC_WITH_SHA = 0x060140,
    SSL_CK_DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0,
    SSL_CK_DES_192_EDE3_CBC_WITH_SHA = 0x0701c0,
    SSL_CK_RC4_64_WITH_MD5 = 0x080080,
    SSL_CK_DES_64_CFB64_WITH_MD5_1 = 0xff0800,
    SSL_CK_NULL = 0xff0810
}