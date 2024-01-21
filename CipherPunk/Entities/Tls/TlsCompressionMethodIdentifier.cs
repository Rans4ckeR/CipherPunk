// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
namespace CipherPunk;

internal enum TlsCompressionMethodIdentifier : byte
{
    NULL = 0,
    DEFLATE = 1,
    LZS = 64
}