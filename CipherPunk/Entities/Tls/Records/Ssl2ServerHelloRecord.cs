namespace CipherPunk;

using System.Buffers.Binary;

public sealed record Ssl2ServerHelloRecord
{
    public Ssl2ServerHelloRecord(ReadOnlySpan<byte> data)
    {
        int index = 0;

        ushort messageLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
        MessageType = data.TakeByte(ref index);
        SessionIdHit = data.TakeByte(ref index);
        CertificateType = data.TakeByte(ref index);
        Version = data.TakeBytes(ref index, 2);
        ushort certificateLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
        ushort cipherSpecLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
        ushort connectionIdLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt16(data.TakeBytes(ref index, 2)));
        Certificate = data.TakeBytes(ref index, certificateLength);
        CipherSpecs = data.TakeBytes(ref index, cipherSpecLength);
        ConnectionId = data.TakeBytes(ref index, connectionIdLength);
    }

    // 2 bytes
    public byte[] MessageLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(1 + 1 + 1 + Version.Length + CertificateLength.Length + CipherSpecLength.Length + ConnectionIdLength.Length + Certificate.Length + CipherSpecs.Length + ConnectionId.Length) | (1 << 15))).Skip(2).ToArray(); // + 1 for size of MessageType, SessionIdHit, CertificateType

    public byte MessageType { get; }

    public byte SessionIdHit { get; }

    public byte CertificateType { get; }

    // 2 bytes
    public byte[] Version { get; }

    // 2 bytes
    public byte[] CertificateLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)Certificate.Length));

    // 2 bytes
    public byte[] CipherSpecLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)CipherSpecs.Length));

    // 2 bytes
    public byte[] ConnectionIdLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)ConnectionId.Length));

    public byte[] Certificate { get; }

    public byte[] CipherSpecs { get; }

    public byte[] ConnectionId { get; }

    public byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(MessageLength);
        result.Add(MessageType);
        result.Add(SessionIdHit);
        result.Add(CertificateType);
        result.AddRange(ConnectionIdLength);
        result.AddRange(Certificate);
        result.AddRange(CipherSpecs);
        result.AddRange(ConnectionId);

        return [.. result];
    }
}