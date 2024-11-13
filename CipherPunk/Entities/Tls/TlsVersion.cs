// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
namespace CipherPunk;

#pragma warning disable CA1028 // Enum Storage should be Int32
public enum TlsVersion : ushort
#pragma warning restore CA1028 // Enum Storage should be Int32
{
    SSL2_PROTOCOL_VERSION = Windows.Win32.SslProviderProtocolId.SSL2_PROTOCOL_VERSION,
    SSL3_PROTOCOL_VERSION = Windows.Win32.SslProviderProtocolId.SSL3_PROTOCOL_VERSION,
    TLS1_0_PROTOCOL_VERSION = Windows.Win32.SslProviderProtocolId.TLS1_0_PROTOCOL_VERSION,
    TLS1_1_PROTOCOL_VERSION = Windows.Win32.SslProviderProtocolId.TLS1_1_PROTOCOL_VERSION,
    TLS1_2_PROTOCOL_VERSION = Windows.Win32.SslProviderProtocolId.TLS1_2_PROTOCOL_VERSION,
    TLS1_3_PROTOCOL_VERSION = Windows.Win32.SslProviderProtocolId.TLS1_3_PROTOCOL_VERSION
}