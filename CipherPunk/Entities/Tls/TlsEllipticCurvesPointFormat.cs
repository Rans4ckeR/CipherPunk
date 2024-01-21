// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

internal enum TlsEllipticCurvesPointFormat : byte
{
    uncompressed = 0,
    ansiX962_compressed_prime = 1,
    ansiX962_compressed_char2 = 2
}