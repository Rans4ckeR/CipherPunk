namespace CipherPunk;

using System.Collections.Frozen;
using Windows.Win32;

internal sealed class WindowsEllipticCurveDocumentationService(IEllipticCurveIdentifierService ellipticCurveIdentifierService) : IWindowsEllipticCurveDocumentationService
{
    private FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>>? windowsDocumentationEllipticCurveConfigurations;

    public FrozenSet<WindowsDocumentationEllipticCurveConfiguration> GetWindowsDocumentationEllipticCurveConfigurations(WindowsVersion windowsVersion)
        => (windowsDocumentationEllipticCurveConfigurations ??= BuildWindowsDocumentationEllipticCurveConfigurations()).Where(q => q.Key <= windowsVersion).MaxBy(q => q.Key).Value;

    private FrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>> BuildWindowsDocumentationEllipticCurveConfigurations()
    {
        var windows10V1607OrServer2016 = FrozenSet.ToFrozenSet<WindowsDocumentationEllipticCurveConfiguration>(
        [
            new(1, PInvoke.BCRYPT_ECC_CURVE_25519, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_25519), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_25519, TlsSupportedGroup.x25519, false, true),
            new(2, PInvoke.BCRYPT_ECC_CURVE_NISTP256, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP256), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP256, TlsSupportedGroup.secp256r1, true, true),
            new(3, PInvoke.BCRYPT_ECC_CURVE_NISTP384, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP384), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP384, TlsSupportedGroup.secp384r1, true, true),
            new(4, PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, TlsSupportedGroup.brainpoolP256r1, false, false),
            new(5, PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, TlsSupportedGroup.brainpoolP384r1, false, false),
            new(6, PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, TlsSupportedGroup.brainpoolP512r1, false, false),
            new(7, PInvoke.BCRYPT_ECC_CURVE_NISTP192, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192, TlsSupportedGroup.secp192r1, false, false),
            new(8, PInvoke.BCRYPT_ECC_CURVE_NISTP224, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224, TlsSupportedGroup.secp224r1, false, false),
            new(9, PInvoke.BCRYPT_ECC_CURVE_NISTP521, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521, TlsSupportedGroup.secp521r1, true, false),
            new(10, PInvoke.BCRYPT_ECC_CURVE_SECP160K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1, TlsSupportedGroup.secp160k1, false, false),
            new(11, PInvoke.BCRYPT_ECC_CURVE_SECP160R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1, TlsSupportedGroup.secp160r1, false, false),
            new(12, PInvoke.BCRYPT_ECC_CURVE_SECP160R2, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2, TlsSupportedGroup.secp160r2, false, false),
            new(13, PInvoke.BCRYPT_ECC_CURVE_SECP192K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1, TlsSupportedGroup.secp192k1, false, false),
            new(14, PInvoke.BCRYPT_ECC_CURVE_SECP192R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1, TlsSupportedGroup.secp192r1, false, false),
            new(15, PInvoke.BCRYPT_ECC_CURVE_SECP224K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1, TlsSupportedGroup.secp224k1, false, false),
            new(16, PInvoke.BCRYPT_ECC_CURVE_SECP224R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1, TlsSupportedGroup.secp224r1, false, false),
            new(17, PInvoke.BCRYPT_ECC_CURVE_SECP256K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1, TlsSupportedGroup.secp256k1, false, false),
            new(18, PInvoke.BCRYPT_ECC_CURVE_SECP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1, TlsSupportedGroup.secp256r1, false, false),
            new(19, PInvoke.BCRYPT_ECC_CURVE_SECP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1, TlsSupportedGroup.secp384r1, false, false),
            new(20, PInvoke.BCRYPT_ECC_CURVE_SECP521R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1, TlsSupportedGroup.secp521r1, false, false)
        ]);
        var windows10V1507 = FrozenSet.ToFrozenSet<WindowsDocumentationEllipticCurveConfiguration>(
        [
            new(1, PInvoke.BCRYPT_ECC_CURVE_NISTP256, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP256), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP256, TlsSupportedGroup.secp256r1, true, true),
            new(2, PInvoke.BCRYPT_ECC_CURVE_NISTP384, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP384), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP384, TlsSupportedGroup.secp384r1, true, true),
            new(3, PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP256R1, TlsSupportedGroup.brainpoolP256r1, false, false),
            new(4, PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP384R1, TlsSupportedGroup.brainpoolP384r1, false, false),
            new(5, PInvoke.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_BRAINPOOLP512R1, TlsSupportedGroup.brainpoolP512r1, false, false),
            new(6, PInvoke.BCRYPT_ECC_CURVE_NISTP192, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP192, TlsSupportedGroup.secp192r1, false, false),
            new(7, PInvoke.BCRYPT_ECC_CURVE_NISTP224, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP224, TlsSupportedGroup.secp224r1, false, false),
            new(8, PInvoke.BCRYPT_ECC_CURVE_NISTP521, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_NISTP521, TlsSupportedGroup.secp521r1, true, false),
            new(9, PInvoke.BCRYPT_ECC_CURVE_SECP160K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160K1, TlsSupportedGroup.secp160k1, false, false),
            new(10, PInvoke.BCRYPT_ECC_CURVE_SECP160R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R1, TlsSupportedGroup.secp160r1, false, false),
            new(11, PInvoke.BCRYPT_ECC_CURVE_SECP160R2, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP160R2, TlsSupportedGroup.secp160r2, false, false),
            new(12, PInvoke.BCRYPT_ECC_CURVE_SECP192K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192K1, TlsSupportedGroup.secp192k1, false, false),
            new(13, PInvoke.BCRYPT_ECC_CURVE_SECP192R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP192R1, TlsSupportedGroup.secp192r1, false, false),
            new(14, PInvoke.BCRYPT_ECC_CURVE_SECP224K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224K1, TlsSupportedGroup.secp224k1, false, false),
            new(15, PInvoke.BCRYPT_ECC_CURVE_SECP224R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP224R1, TlsSupportedGroup.secp224r1, false, false),
            new(16, PInvoke.BCRYPT_ECC_CURVE_SECP256K1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256K1, TlsSupportedGroup.secp256k1, false, false),
            new(17, PInvoke.BCRYPT_ECC_CURVE_SECP256R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP256R1, TlsSupportedGroup.secp256r1, false, false),
            new(18, PInvoke.BCRYPT_ECC_CURVE_SECP384R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP384R1, TlsSupportedGroup.secp384r1, false, false),
            new(19, PInvoke.BCRYPT_ECC_CURVE_SECP521R1, ellipticCurveIdentifierService.GetIdentifier(BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1), BCRYPT_ECC_CURVE.BCRYPT_ECC_CURVE_SECP521R1, TlsSupportedGroup.secp521r1, false, false)
        ]);

        return FrozenDictionary.ToFrozenDictionary<WindowsVersion, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>>(
        [
            new(WindowsVersion.Windows10V1607OrServer2016, windows10V1607OrServer2016),
            new(WindowsVersion.Windows10V1507, windows10V1507),
            new(WindowsVersion.WindowsVistaOrServer2008, FrozenSet<WindowsDocumentationEllipticCurveConfiguration>.Empty)
        ]);
    }
}