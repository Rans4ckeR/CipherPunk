namespace CipherPunk;

public enum SchannelProtocolStatus
{
    /// <summary>
    /// Unless the SSPI caller explicitly disables this protocol version using the SCH_CREDENTIALS structure, Schannel SSP may negotiate this protocol version with a supporting peer.
    /// </summary>
    Enabled,

    /// <summary>
    /// Disabled by default: Unless the SSPI caller explicitly requests this protocol version using the deprecated SCHANNEL_CRED structure, Schannel SSP will not negotiate this protocol version.
    /// </summary>
    DisabledByDefault,

    /// <summary>
    /// Schannel SSP will not negotiate this protocol version regardless of the settings the SSPI caller may specify.
    /// </summary>
    Disabled,

    /// <summary>
    /// Not configured, the default OS setting is used.
    /// </summary>
    OsDefault
}