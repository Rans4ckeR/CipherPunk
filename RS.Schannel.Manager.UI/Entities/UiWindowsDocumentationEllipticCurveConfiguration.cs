namespace RS.Schannel.Manager.UI;

using RS.Schannel.Manager.API;

internal readonly record struct UiWindowsDocumentationEllipticCurveConfiguration(
    ushort Priority,
    string Name,
    string? Identifier,
    BCRYPT_ECC_CURVE Code,
    TlsSupportedGroup TlsSupportedGroup,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault);