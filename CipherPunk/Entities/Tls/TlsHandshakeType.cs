// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

internal enum TlsHandshakeType : byte
{
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    hello_retry_request = 6,
    Unassigned = 7,
    encrypted_extensions = 8,
    request_connection_id = 9,
    new_connection_id = 10,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    client_certificate_request = 17,
    finished = 20,
    certificate_url = 21,
    certificate_status = 22,
    supplemental_data = 23,
    key_update = 24,
    compressed_certificate = 25,
    ekt_key = 26,
    message_hash = 254
}