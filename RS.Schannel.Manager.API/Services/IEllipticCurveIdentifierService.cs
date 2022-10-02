namespace RS.Schannel.Manager.API;

public interface IEllipticCurveIdentifierService
{
    Dictionary<BCRYPT_ECC_CURVE, string?> GetEllipticCurveIdentifiers();

    public string? GetIdentifier(string code);

    public string? GetIdentifier(BCRYPT_ECC_CURVE code);
}