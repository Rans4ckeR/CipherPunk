namespace CipherPunk;

using Windows.Win32;

internal sealed class WindowsEllipticCurveDocumentationService : IWindowsEllipticCurveDocumentationService
{
    private readonly IEllipticCurveIdentifierService ellipticCurveIdentifierService;

    private Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>>? windowsDocumentationEllipticCurveConfigurations;

    public WindowsEllipticCurveDocumentationService(IEllipticCurveIdentifierService ellipticCurveIdentifierService)
    {
        this.ellipticCurveIdentifierService = ellipticCurveIdentifierService;
    }

    public Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>> GetWindowsDocumentationEllipticCurveConfigurations()
        => windowsDocumentationEllipticCurveConfigurations ??= BuildWindowsDocumentationEllipticCurveConfigurations();

    public List<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsSchannelVersion windowsSchannelVersion)
    {
        return GetWindowsDocumentationEllipticCurveConfigurations().Any(q => q.Key >= windowsSchannelVersion) ? GetWindowsDocumentationEllipticCurveConfigurations().FirstOrDefault(q => q.Key >= windowsSchannelVersion).Value : new();
    }

    private Dictionary<WindowsSchannelVersion, List<WindowsDocumentationEllipticCurveConfiguration>> BuildWindowsDocumentationEllipticCurveConfigurations()
    {
        var windows10v1607OrServer2016 = new List<WindowsDocumentationEllipticCurveConfiguration>
        {
            new(PInvoke.BCRYPT_ECC_CURVE_25519, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_25519), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_25519, TlsSupportedGroup.x25519, false, true),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP256, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP256), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP256, TlsSupportedGroup.secp256r1, true, true),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP384, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP384), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP384, TlsSupportedGroup.secp384r1, true, true),
            new(PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, TlsSupportedGroup.brainpoolP256r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, TlsSupportedGroup.brainpoolP384r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, TlsSupportedGroup.brainpoolP512r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP192, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192, TlsSupportedGroup.secp192r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP224, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224, TlsSupportedGroup.secp224r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP521, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521, TlsSupportedGroup.secp521r1 , true, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP160K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1, TlsSupportedGroup.secp160k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP160R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1, TlsSupportedGroup.secp160r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP160R2, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2, TlsSupportedGroup.secp160r2, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP192K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1, TlsSupportedGroup.secp192k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP192R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1, TlsSupportedGroup.secp192r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP224K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1, TlsSupportedGroup.secp224k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP224R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1, TlsSupportedGroup.secp224r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP256K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1, TlsSupportedGroup.secp256k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1, TlsSupportedGroup.secp256r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1, TlsSupportedGroup.secp384r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP521R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1, TlsSupportedGroup.secp521r1, false, false)
        };
        var windows10v1507 = new List<WindowsDocumentationEllipticCurveConfiguration>
        {
            new(PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, TlsSupportedGroup.brainpoolP256r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, TlsSupportedGroup.brainpoolP384r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, TlsSupportedGroup.brainpoolP512r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP192, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192, TlsSupportedGroup.secp192r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP224, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224, TlsSupportedGroup.secp224r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_NISTP521, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521, TlsSupportedGroup.secp521r1, true, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP160K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1, TlsSupportedGroup.secp160k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP160R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1, TlsSupportedGroup.secp160r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP160R2, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2, TlsSupportedGroup.secp160r2, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP192K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1, TlsSupportedGroup.secp192k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP192R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1, TlsSupportedGroup.secp192r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP224K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1, TlsSupportedGroup.secp224k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP224R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1, TlsSupportedGroup.secp224r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP256K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1, TlsSupportedGroup.secp256k1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1, TlsSupportedGroup.secp256r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1, TlsSupportedGroup.secp384r1, false, false),
            new(PInvoke.BCRYPT_ECC_CURVE_SECP521R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1, TlsSupportedGroup.secp521r1, false, false)
        };

        return new()
        {
            { WindowsSchannelVersion.Windows10v1607OrServer2016, windows10v1607OrServer2016 },
            { WindowsSchannelVersion.Windows10v1507, windows10v1507 }
        };
    }
}