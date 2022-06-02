namespace RS.Schannel.Manager.API;

public readonly record struct WindowsDocumentationEllipticCurveConfiguration(
    string EllipticCurveString,
    bool AllowedByUseStrongCryptographyFlag,
    bool EnabledByDefault);