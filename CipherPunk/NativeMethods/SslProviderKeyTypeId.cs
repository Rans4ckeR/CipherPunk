// ReSharper disable InconsistentNaming
namespace Windows.Win32;

#pragma warning disable CA1028 // Enum Storage should be Int32
public enum SslProviderKeyTypeId : uint
#pragma warning restore CA1028 // Enum Storage should be Int32
{
    // Key Types
    // ECC curve types
    TLS_ECC_P256_CURVE_KEY_TYPE = 23, // secp256r1 _P256
    TLS_ECC_P384_CURVE_KEY_TYPE = 24, // secp384r1 _P384
    TLS_ECC_P521_CURVE_KEY_TYPE = 25 // secp521r1 _P521
}