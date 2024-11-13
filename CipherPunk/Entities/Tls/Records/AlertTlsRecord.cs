namespace CipherPunk;

internal sealed record AlertTlsRecord : TlsRecord
{
    public AlertTlsRecord(ReadOnlySpan<byte> data)
        : base(data)
    {
        int index = TlsRecordHeader.Size;

        Level = data.TakeByte(ref index);
        Description = data.TakeByte(ref index);
    }

    public byte Level { get; }

    public byte Description { get; }

    protected override byte[] GetRecordTypeBytes()
    {
        var result = new List<byte>
        {
            Level,
            Description
        };

        return [.. result];
    }
}