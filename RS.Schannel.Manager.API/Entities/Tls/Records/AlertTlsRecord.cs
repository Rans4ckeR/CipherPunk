namespace RS.Schannel.Manager.API;

public sealed record AlertTlsRecord : TlsRecord
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

    public static implicit operator TlsAlert(AlertTlsRecord alertTlsRecord)
    {
        return new((TlsAlertLevel)alertTlsRecord.Level, (TlsAlertDescription)alertTlsRecord.Description);
    }

    protected override byte[] GetRecordTypeBytes()
    {
        var result = new List<byte>
        {
            Level,
            Description
        };

        return result.ToArray();
    }
}