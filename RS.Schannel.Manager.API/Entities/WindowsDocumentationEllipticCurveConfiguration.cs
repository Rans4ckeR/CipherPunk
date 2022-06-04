namespace RS.Schannel.Manager.API;

public readonly record struct WindowsDocumentationEllipticCurveConfiguration(
    string Name,
    string Identifier,
    BCRYPT_ECC_CURVE Code,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault);