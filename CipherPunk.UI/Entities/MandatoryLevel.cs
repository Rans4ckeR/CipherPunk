namespace CipherPunk.UI;

internal enum MandatoryLevel
{
    /// <summary>
    /// Anonymous logged on processes. Write access is mostly blocked.
    /// </summary>
    Untrusted,

    /// <summary>
    /// Used for AppContainers, browsers that access the internet and prevent most write access to objects on the system—specifically the registry and filesystem.
    /// </summary>
    Low,

    /// <summary>
    /// Default for most processes. For authenticated users.
    /// </summary>
    Medium,

    /// <summary>
    /// Default for most processes. For authenticated users. With UIAccess rights.
    /// </summary>
    MediumUiAccess,

    MediumPlus,

    /// <summary>
    /// Administrator-level processes. (Elevated) process with UAC.
    /// </summary>
    High,

    /// <summary>
    /// Reserved for system services/processes.
    /// </summary>
    System,

    /// <summary>
    /// Not seen to be used by default. Windows Internals book says it can be set by a kernel-mode caller.
    /// </summary>
    ProtectedProcess,

    SecureProcess
}