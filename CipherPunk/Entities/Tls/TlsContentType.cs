// ReSharper disable InconsistentNaming
// ReSharper disable UnusedMember.Global
#pragma warning disable SA1300 // Element should begin with upper-case letter
namespace CipherPunk;

internal enum TlsContentType : byte
{
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    heartbeat = 24,
    tls12_cid = 25,
    ACK = 26
}