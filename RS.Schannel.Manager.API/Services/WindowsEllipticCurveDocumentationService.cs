namespace RS.Schannel.Manager.API;

internal sealed class WindowsEllipticCurveDocumentationService : IWindowsEllipticCurveDocumentationService
{
    private Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>>? windowsDocumentationEllipticCurveConfigurations;

    public Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>> GetWindowsDocumentationEllipticCurveConfigurations()
        => windowsDocumentationEllipticCurveConfigurations ??= BuildWindowsDocumentationEllipticCurveConfigurations();

    public List<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsSchannelVersion windowsSchannelVersion)
    {
        return GetWindowsDocumentationEllipticCurveConfigurations().Any(q => q.Key >= windowsSchannelVersion) ? GetWindowsDocumentationEllipticCurveConfigurations().FirstOrDefault(q => q.Key >= windowsSchannelVersion).Value : new List<WindowsDocumentationEllipticCurveConfiguration>();
    }

    private static Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>> BuildWindowsDocumentationEllipticCurveConfigurations()
    {
        var windows10v1607OrServer2016 = new List<WindowsDocumentationEllipticCurveConfiguration>
        {
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_25519, false, true),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP256, true, true),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP384, true, true),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP192, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP224, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP521, true, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP160K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP160R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP160R2, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP192K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP192R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP224K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP224R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP256K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP256R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP384R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP521R1, false, false)
        };
        var windows10v1507 = new List<WindowsDocumentationEllipticCurveConfiguration>
        {
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP192, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP224, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_NISTP521, true, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP160K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP160R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP160R2, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP192K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP192R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP224K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP224R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP256K1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP256R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP384R1, false, false),
            new(EllipticCurveNames.BCRYPT_ECC_CURVE_SECP521R1, false, false)
        };

        return new Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>>
        {
            { WindowsSchannelVersion.Windows10v1607OrServer2016, windows10v1607OrServer2016 },
            { WindowsSchannelVersion.Windows10v1507, windows10v1507 }
        };
    }
}