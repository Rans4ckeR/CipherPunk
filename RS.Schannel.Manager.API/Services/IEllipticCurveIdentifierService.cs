namespace RS.Schannel.Manager.API;

public interface IEllipticCurveIdentifierService
{
    Dictionary<BCRYPT_ECC_CURVE, string?> GetEllipticCurveIdentifiers();

    string? GetIdentifier(string code);

    string? GetIdentifier(BCRYPT_ECC_CURVE code);
}