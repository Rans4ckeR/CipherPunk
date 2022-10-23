namespace CipherPunk;

using System;

public sealed class GroupPolicyServiceException : Exception
{
    public GroupPolicyServiceException(string message)
        : base(message)
    {
    }
}