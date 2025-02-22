﻿// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

#pragma warning disable CA1028 // Enum Storage should be Int32
public enum TlsSupportedGroup : ushort
#pragma warning restore CA1028 // Enum Storage should be Int32
{
    sect163k1 = 0x0001,
    sect163r1 = 0x0002,
    sect163r2 = 0x0003,
    sect193r1 = 0x0004,
    sect193r2 = 0x0005,
    sect233k1 = 0x0006,
    sect233r1 = 0x0007,
    sect239k1 = 0x0008,
    sect283k1 = 0x0009,
    sect283r1 = 0x000A,
    sect409k1 = 0x000B,
    sect409r1 = 0x000C,
    sect571k1 = 0x000D,
    sect571r1 = 0x000E,
    secp160k1 = 0x000F,
    secp160r1 = 0x0010,
    secp160r2 = 0x0011,
    secp192k1 = 0x0012,
    secp192r1 = 0x0013,
    secp224k1 = 0x0014,
    secp224r1 = 0x0015,
    secp256k1 = 0x0016,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    brainpoolP256r1 = 0x001A,
    brainpoolP384r1 = 0x001B,
    brainpoolP512r1 = 0x001C,
    x25519 = 0x001D,
    x448 = 0x001E,
    brainpoolP256r1tls13 = 0x001F,
    brainpoolP384r1tls13 = 0x0020,
    brainpoolP512r1tls13 = 0x0021,
    GC256A = 0x0022,
    GC256B = 0x0023,
    GC256C = 0x0024,
    GC256D = 0x0025,
    GC512A = 0x0026,
    GC512B = 0x0027,
    GC512C = 0x0028,
    curveSM2 = 0x0029,
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
    arbitrary_explicit_prime_curves = 0xFF01,
    arbitrary_explicit_char2_curves = 0xFF02
}