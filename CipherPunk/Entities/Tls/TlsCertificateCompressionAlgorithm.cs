// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

internal enum TlsCertificateCompressionAlgorithm : ushort
{
    zlib = 1,
    brotli = 2,
    zstd = 3
}