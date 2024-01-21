namespace CipherPunk;

using System.Collections.Frozen;

public interface IEllipticCurveIdentifierService
{
    FrozenDictionary<BCRYPT_ECC_CURVE, string?> GetEllipticCurveIdentifiers();

    string? GetIdentifier(string code);

    string? GetIdentifier(BCRYPT_ECC_CURVE code);
}