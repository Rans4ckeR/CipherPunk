﻿namespace RS.Schannel.Manager.API;

using System.Buffers.Binary;

public abstract record TlsRecord
{
    protected TlsRecord(ReadOnlySpan<byte> data)
    {
        TlsRecordHeader = new TlsRecordHeader(data);

        int index = TlsRecordHeader.Size;

        switch ((TlsContentType)TlsRecordHeader.TlsRecordContentType)
        {
            case TlsContentType.alert:
                TlsHandshakeHeaderMessageType = byte.MinValue;
                HandshakeClientVersion = Array.Empty<byte>();
                HandshakeClientRandom = Array.Empty<byte>();
                HandshakeSessionId = Array.Empty<byte>();
                HandshakeExtensions = new();
                return;
        }

        TlsHandshakeHeaderMessageType = data.TakeByte(ref index);
        uint handshakeMessageLength = BinaryPrimitives.ReverseEndianness(BitConverter.ToUInt32(new byte[] { 0x00 }.Concat(data.TakeBytes(ref index, 3)).ToArray()));
        HandshakeClientVersion = data.TakeBytes(ref index, 2);
        HandshakeClientRandom = data.TakeBytes(ref index, 32);
        byte handshakeSessionIdLength = data.TakeByte(ref index);
        HandshakeSessionId = data.TakeBytes(ref index, handshakeSessionIdLength);
        HandshakeExtensions = new();
    }

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

                switch ((TlsHandshakeType)tlsHandshakeHeaderMessageType)
                {
                    case TlsHandshakeType.client_hello:
                        return new ClientHelloTlsRecord(data);
                    case TlsHandshakeType.server_hello:
                        return new ServerHelloTlsRecord(data);
                    default:
                        throw new ArgumentOutOfRangeException();
                }

            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    protected TlsRecord(TlsVersion tlsVersion, TlsContentType tlsContentType, TlsHandshakeType tlsHandshakeType)
    {
        TlsRecordHeader = new TlsRecordHeader(this, tlsVersion, tlsContentType);
        TlsHandshakeHeaderMessageType = (byte)tlsHandshakeType;

        if (tlsVersion is TlsVersion.TLS1_3_PROTOCOL_VERSION)
            tlsVersion = TlsVersion.TLS1_2_PROTOCOL_VERSION;

        HandshakeClientVersion = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)tlsVersion));
        HandshakeClientRandom = new byte[32];

        new Random().NextBytes(HandshakeClientRandom);

        HandshakeSessionId = new byte[32];

        new Random().NextBytes(HandshakeSessionId);

        HandshakeExtensions = new();
    }

    public int HandshakeMessageNumberOfBytes => HandshakeClientVersion.Length + HandshakeClientRandom.Length + 1 + HandshakeSessionId.Length + GetRecordTypeBytes().Length + HandshakeExtensionsLength.Length + HandshakeExtensions.Sum(q => q.GetBytes().Length); // + 1 for HandshakeSessionIdLength

    public TlsRecordHeader TlsRecordHeader { get; }

    public byte TlsHandshakeHeaderMessageType { get; }

    // 3 bytes
    public byte[] HandshakeMessageLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness(HandshakeMessageNumberOfBytes)).Skip(1).ToArray();

    // 2 bytes
    public byte[] HandshakeClientVersion { get; }

    // 32 bytes
    public byte[] HandshakeClientRandom { get; }

    public byte HandshakeSessionIdLength => (byte)HandshakeSessionId.Length;

    // 32 bytes
    public byte[] HandshakeSessionId { get; }

    // 2 bytes
    public byte[] HandshakeExtensionsLength => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)HandshakeExtensions.Sum(q => q.GetBytes().Length)));

    public List<HandshakeExtension> HandshakeExtensions { get; protected set; }

    protected abstract byte[] GetRecordTypeBytes();

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

        return result.ToArray();
    }

    public byte[] GetMessageBytes()
    {
        var result = new List<byte>();

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

        return result.ToArray();
    }
}