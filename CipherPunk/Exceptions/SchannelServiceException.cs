namespace CipherPunk;

using System;

public sealed class SchannelServiceException : Exception
{
    public SchannelServiceException(string message)
        : base(message)
    {
    }
}