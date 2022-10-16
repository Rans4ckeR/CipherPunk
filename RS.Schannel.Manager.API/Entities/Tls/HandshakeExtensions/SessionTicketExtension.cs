namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public sealed record SessionTicketExtension : HandshakeExtension
{
    // 2 bytes
    public override byte[] ExtensionType => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsExtensionType.session_ticket));

    // 2 bytes
    public override byte[] ExtensionTypeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)0)); // no session_ticket

    public override byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(ExtensionType);
        result.AddRange(ExtensionTypeLength);

        return result.ToArray();
    }
}