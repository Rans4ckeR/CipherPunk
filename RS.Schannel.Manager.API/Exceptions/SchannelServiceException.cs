namespace RS.Schannel.Manager.API;

using System;

public sealed class SchannelServiceException : Exception
{
    public SchannelServiceException(string message)
        : base(message)
    {
    }
}