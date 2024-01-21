// ReSharper disable UnusedMember.Global
// ReSharper disable InconsistentNaming
namespace CipherPunk;

[Flags]
public enum SchannelCertificateMappingMethod
{
    Subject_Issuer = 0x0001,
    IssuerCertificate = 0x0002,
    UPN = 0x0004,
    S4U2Self = 0x0008,
    S4U2SelfExplicit = 0x0010
}