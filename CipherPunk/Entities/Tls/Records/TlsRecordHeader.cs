﻿using System.Buffers.Binary;

namespace CipherPunk;

internal sealed record TlsRecordHeader
{
    public TlsRecordHeader(ReadOnlySpan<byte> data)
    {
        int index = 0;

        TlsRecordContentType = data.TakeByte(ref index);
        TlsRecordVersion = data.TakeBytes(ref index, 2);

        byte[] tlsRecordLength = data.TakeBytes(ref index, 2);

        GetTlsRecordLength = () => tlsRecordLength;
    }

    public TlsRecordHeader(TlsRecord tlsRecord, TlsVersion tlsVersion, TlsContentType tlsContentType)
    {
        TlsRecordContentType = (byte)tlsContentType;

        if (tlsVersion is not TlsVersion.SSL3_PROTOCOL_VERSION)
            tlsVersion = TlsVersion.TLS1_0_PROTOCOL_VERSION;

        TlsRecordVersion = BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)tlsVersion));
        TlsRecord = tlsRecord;
        GetTlsRecordLength = () => BitConverter.GetBytes(BinaryPrimitives.ReverseEndianness((ushort)TlsRecord.GetMessageBytes().Length));
    }

    public static int Size => 5;

    public byte TlsRecordContentType { get; }

    // 2 bytes
    public byte[] TlsRecordVersion { get; }

    // 2 bytes
    public byte[] TlsRecordLength => GetTlsRecordLength();

    public TlsRecord? TlsRecord { get; }

    private Func<byte[]> GetTlsRecordLength { get; }

    public byte[] GetBytes()
    {
        var result = new List<byte> { TlsRecordContentType };

        result.AddRange(TlsRecordVersion);
        result.AddRange(TlsRecordLength);

        return [.. result];
    }
}