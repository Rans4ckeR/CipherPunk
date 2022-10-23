namespace CipherPunk.UI;

using CipherPunk;

internal readonly record struct UiWindowsDocumentationEllipticCurveConfiguration(
    ushort Priority,
    string Name,
    string? Identifier,
    BCRYPT_ECC_CURVE Code,
    TlsSupportedGroup TlsSupportedGroup,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault);