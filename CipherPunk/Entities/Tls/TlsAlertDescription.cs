﻿// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

internal enum TlsAlertDescription : ushort
{
    close_notify = 0x0000,
    unexpected_message = 0x000A,
    bad_record_mac = 0x0014,
    decryption_failed_RESERVED = 0x0015,
    record_overflow = 0x0016,
    decompression_failure_RESERVED = 0x001E,
    handshake_failure = 0x0028,
    no_certificate_RESERVED = 0x0029,
    bad_certificate = 0x002A,
    unsupported_certificate = 0x002B,
    certificate_revoked = 0x002C,
    certificate_expired = 0x002D,
    certificate_unknown = 0x002E,
    illegal_parameter = 0x002F,
    unknown_ca = 0x0030,
    access_denied = 0x0031,
    decode_error = 0x0032,
    decrypt_error = 0x0033,
    too_many_cids_requested = 0x0034,
    export_restriction_RESERVED = 0x003C,
    protocol_version = 0x0046,
    insufficient_security = 0x0047,
    internal_error = 0x0050,
    inappropriate_fallback = 0x0056,
    user_canceled = 0x005A,
    no_renegotiation_RESERVED = 0x0064,
    missing_extension = 0x006D,
    unsupported_extension = 0x006E,
    certificate_unobtainable_RESERVED = 0x006F,
    unrecognized_name = 0x0070,
    bad_certificate_status_response = 0x0071,
    bad_certificate_hash_value_RESERVED = 0x0072,
    unknown_psk_identity = 0x0073,
    certificate_required = 0x0074,
    no_application_protocol = 0x0078
}