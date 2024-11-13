// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
namespace Windows.Win32;

#pragma warning disable CA1028 // Enum Storage should be Int32
public enum SslProviderProtocolId : ushort
#pragma warning restore CA1028 // Enum Storage should be Int32
{
    SSL2_PROTOCOL_VERSION = 0x0002,
    SSL3_PROTOCOL_VERSION = 0x0300,
    TLS1_PROTOCOL_VERSION = 0x0301,
    TLS1_0_PROTOCOL_VERSION = TLS1_PROTOCOL_VERSION,
    TLS1_1_PROTOCOL_VERSION = 0x0302,
    TLS1_2_PROTOCOL_VERSION = 0x0303,
    TLS1_3_PROTOCOL_VERSION = 0x0304,
    DTLS1_0_PROTOCOL_VERSION = 0xfeff,
    DTLS1_2_PROTOCOL_VERSION = 0xfefd
}