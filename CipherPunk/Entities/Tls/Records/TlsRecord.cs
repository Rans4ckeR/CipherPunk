using System.Buffers.Binary;
using System.Collections.Frozen;
using System.Security.Cryptography;

namespace CipherPunk;

internal abstract record TlsRecord
{
    protected TlsRecord(ReadOnlySpan<byte> data)
    {
        TlsRecordHeader = new(data);

        int index = TlsRecordHeader.Size;

        switch ((TlsContentType)TlsRecordHeader.TlsRecordContentType)
        {
            case TlsContentType.alert:
                TlsHandshakeHeaderMessageType = byte.MinValue;
                HandshakeClientVersion = [];
                HandshakeClientRandom = [];
                HandshakeSessionId = [];
                HandshakeExtensions = [];
                return;
        }

        TlsHandshakeHeaderMessageType = data.TakeByte(ref index);
#pragma warning disable IDE0059 // Unnecessary assignment of a value
        // ReSharper disable once UnusedVariable
        uint handshakeMessageLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt32(new byte[] { 0x00 }.Concat(data.TakeBytes(ref index, 3)).ToArray()));
#pragma warning restore IDE0059 // Unnecessary assignment of a value
        HandshakeClientVersion = data.TakeBytes(ref index, 2);
        HandshakeClientRandom = data.TakeBytes(ref index, 32);
        byte handshakeSessionIdLength = data.TakeByte(ref index);
        HandshakeSessionId = data.TakeBytes(ref index, handshakeSessionIdLength);
        HandshakeExtensions = [];
    }

    protected TlsRecord(TlsVersion tlsVersion, TlsContentType tlsContentType, TlsHandshakeType tlsHandshakeType)
    {
        TlsRecordHeader = new(this, tlsVersion, tlsContentType);
        TlsHandshakeHeaderMessageType = (byte)tlsHandshakeType;

        if (tlsVersion is TlsVersion.TLS1_3_PROTOCOL_VERSION)
            tlsVersion = TlsVersion.TLS1_2_PROTOCOL_VERSION;

        HandshakeClientVersion = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)tlsVersion));
        HandshakeClientRandom = RandomNumberGenerator.GetBytes(32);
        HandshakeSessionId = RandomNumberGenerator.GetBytes(32);
        HandshakeExtensions = [];
    }

    public int HandshakeMessageNumberOfBytes => HandshakeClientVersion.Length + HandshakeClientRandom.Length + sizeof(byte) + HandshakeSessionId.Length + GetRecordTypeBytes().Length + HandshakeExtensionsLength.Length + HandshakeExtensions.Sum(q => q.GetBytes().Length); // + 1 for HandshakeSessionIdLength

    public TlsRecordHeader TlsRecordHeader { get; }

    public byte TlsHandshakeHeaderMessageType { get; }

    // 3 bytes
    public byte[] HandshakeMessageLength => [.. BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(HandshakeMessageNumberOfBytes)).Skip(1)];

    // 2 bytes
    public byte[] HandshakeClientVersion { get; }

    // 32 bytes
    public byte[] HandshakeClientRandom { get; }

    public byte HandshakeSessionIdLength => (byte)HandshakeSessionId.Length;

    // 32 bytes
    public byte[] HandshakeSessionId { get; }

    // 2 bytes
    public byte[] HandshakeExtensionsLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)HandshakeExtensions.Sum(q => q.GetBytes().Length)));

    public FrozenSet<HandshakeExtension> HandshakeExtensions { get; protected init; }

    public static TlsRecord Parse(ReadOnlySpan<byte> data)
    {
        var tlsRecordHeader = new TlsRecordHeader(data);

        switch ((TlsContentType)tlsRecordHeader.TlsRecordContentType)
        {
            case TlsContentType.alert:
                return new AlertTlsRecord(data);
            case TlsContentType.handshake:
                int index = TlsRecordHeader.Size;
                byte tlsHandshakeHeaderMessageType = data.TakeByte(ref index);

                return (TlsHandshakeType)tlsHandshakeHeaderMessageType switch
                {
                    TlsHandshakeType.client_hello => new ClientHelloTlsRecord(data),
                    TlsHandshakeType.server_hello => new ServerHelloTlsRecord(data),
                    _ => throw new ArgumentOutOfRangeException(nameof(tlsHandshakeHeaderMessageType), (TlsHandshakeType)tlsHandshakeHeaderMessageType, "Unexpected reply from server.")
                };
            default:
                throw new ArgumentOutOfRangeException(nameof(tlsRecordHeader.TlsRecordContentType), (TlsContentType)tlsRecordHeader.TlsRecordContentType, "Unexpected reply from server.");
        }
    }

    public byte[] GetBytes()
    {
        var result = new List<byte>();

        result.AddRange(TlsRecordHeader.GetBytes());
        result.Add(TlsHandshakeHeaderMessageType);
        result.AddRange(HandshakeMessageLength);
        result.AddRange(HandshakeClientVersion);
        result.AddRange(HandshakeClientRandom);
        result.Add(HandshakeSessionIdLength);
        result.AddRange(HandshakeSessionId);
        result.AddRange(GetRecordTypeBytes());
        result.AddRange(HandshakeExtensionsLength);

        foreach (HandshakeExtension handshakeExtension in HandshakeExtensions)
        {
            result.AddRange(handshakeExtension.GetBytes());
        }

        return [.. result];
    }

    public byte[] GetMessageBytes()
    {
        var result = new List<byte>
        {
            TlsHandshakeHeaderMessageType
        };

        result.AddRange(HandshakeMessageLength);
        result.AddRange(HandshakeClientVersion);
        result.AddRange(HandshakeClientRandom);
        result.Add(HandshakeSessionIdLength);
        result.AddRange(HandshakeSessionId);
        result.AddRange(GetRecordTypeBytes());
        result.AddRange(HandshakeExtensionsLength);

        foreach (HandshakeExtension handshakeExtension in HandshakeExtensions)
        {
            result.AddRange(handshakeExtension.GetBytes());
        }

        return [.. result];
    }

    protected abstract byte[] GetRecordTypeBytes();
}