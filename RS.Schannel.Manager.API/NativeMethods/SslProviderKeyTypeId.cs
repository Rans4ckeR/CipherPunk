namespace Windows.Win32;

public enum SslProviderKeyTypeId : uint
{
    // Key Types
    // ECC curve types
#pragma warning disable CA1707 // Identifiers should not contain underscores
    TLS_ECC_P256_CURVE_KEY_TYPE = 23, // secp256r1 _P256

    TLS_ECC_P384_CURVE_KEY_TYPE = 24, // secp384r1 _P384

    TLS_ECC_P521_CURVE_KEY_TYPE = 25 // secp521r1 _P521
#pragma warning restore CA1707 // Identifiers should not contain underscores
}