// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

internal enum TlsPreSharedKeysKeyExchangeMode : byte
{
    psk_ke = 0,
    psk_dhe_ke = 1
}