namespace CipherPunk;

public readonly record struct WindowsDocumentationEllipticCurveConfiguration(
    ushort Priority,
    string Name,
    string? Identifier,
    BCRYPT_ECC_CURVE Code,
    TlsSupportedGroup TlsSupportedGroup,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault);