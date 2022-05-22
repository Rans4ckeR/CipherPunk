namespace Windows.Win32;
public enum SslProviderProtocolId : uint
{
#pragma warning disable CA1707 // Identifiers should not contain underscores
    SSL2_PROTOCOL_VERSION = 0x0002,

    SSL3_PROTOCOL_VERSION = 0x0300,

    TLS1_PROTOCOL_VERSION = 0x0301,

    TLS1_0_PROTOCOL_VERSION = TLS1_PROTOCOL_VERSION,

    TLS1_1_PROTOCOL_VERSION = 0x0302, // NTDDI_VERSION >= NTDDI_WIN7

    TLS1_2_PROTOCOL_VERSION = 0x0303, // NTDDI_VERSION >= NTDDI_WIN7

    TLS1_3_PROTOCOL_VERSION = 0x0304, // NTDDI_VERSION >= NTDDI_WIN10_RS2

    DTLS1_0_PROTOCOL_VERSION = 0xfeff, // NTDDI_VERSION >= NTDDI_WIN8

    DTLS1_2_PROTOCOL_VERSION = 0xfefd // NTDDI_VERSION >= NTDDI_WIN10_RS1
#pragma warning restore CA1707 // Identifiers should not contain underscores
}