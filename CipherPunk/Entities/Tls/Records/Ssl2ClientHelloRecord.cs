namespace CipherPunk;

using System.Buffers.Binary;
using System.Security.Cryptography;

public sealed record Ssl2ClientHelloRecord
{
    public Ssl2ClientHelloRecord(SslCipherSuite[] sslProviderCipherSuiteIds)
    {
        MessageType = (byte)TlsHandshakeType.client_hello;
        Version = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsVersion.SSL2_PROTOCOL_VERSION));
        CipherSpecs = sslProviderCipherSuiteIds.SelectMany(q => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((uint)q)).Skip(1)).ToArray();
        SessionId = [];
        Challenge = RandomNumberGenerator.GetBytes(16);
    }

    /// <summary>
    /// This field is the length of the following data in bytes. The high bit MUST be 1 and is not part of the length.
    /// 2 bytes.
    /// </summary>
    public byte[] MessageLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)(1 + Version.Length + CipherSpecLength.Length + SessionIdLength.Length + ChallengeLength.Length + CipherSpecs.Length + SessionId.Length + Challenge.Length) | (1 << 15))).Skip(2).ToArray(); // + 1 for size of MessageType

    /// <summary>
    /// This field, in conjunction with the <see cref="Version"/> field, identifies a version 2 client hello message. The value should be <see cref="TlsHandshakeType.client_hello"/>.
    /// </summary>
    public byte MessageType { get; }

    /// <summary>
    /// The highest version of the protocol supported by the client.
    /// 2 bytes.
    /// </summary>
    public byte[] Version { get; }

    /// <summary>
    /// This field is the total length of the field <see cref="CipherSpecs"/>. It cannot be zero.
    /// 2 bytes.
    /// </summary>
    public byte[] CipherSpecLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)CipherSpecs.Length));

    /// <summary>
    /// This field must have a value of either zero or 16. If zero, the client is creating a new session. If 16, the <see cref="SessionId"/> field will contain the 16 bytes of session identification.
    /// 2 bytes.
    /// </summary>
    public byte[] SessionIdLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)SessionId.Length));

    /// <summary>
    /// The length in bytes of the client's challenge to the server to authenticate itself. This value must be 32.
    /// 2 bytes.
    /// </summary>
    public byte[] ChallengeLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)Challenge.Length));

    /// <summary>
    /// This is a list of all CipherSpecs the client is willing and able to use.
    /// 3 bytes per item.
    /// </summary>
    public byte[] CipherSpecs { get; }

    /// <summary>
    /// If this field's length is not zero, it will contain the identification for a session that the client wishes to resume.
    /// 0 or 16 bytes.
    /// </summary>
    public byte[] SessionId { get; }

    /// <summary>
    /// The client challenge to the server for the server to identify itself.
    /// 32 bytes.
    /// </summary>
    public byte[] Challenge { get; }

    public byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(MessageLength);
        result.Add(MessageType);
        result.AddRange(Version);
        result.AddRange(CipherSpecLength);
        result.AddRange(SessionIdLength);
        result.AddRange(ChallengeLength);
        result.AddRange(CipherSpecs);
        result.AddRange(SessionId);
        result.AddRange(Challenge);

        return [.. result];
    }
}