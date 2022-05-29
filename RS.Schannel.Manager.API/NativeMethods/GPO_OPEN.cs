namespace RS.Schannel.Manager.API;

// Group Policy Object open / creation flags
internal enum GPO_OPEN : uint
{
    GPO_OPEN_LOAD_REGISTRY = 0x00000001U, // Load the registry files
    GPO_OPEN_READ_ONLY = 0x00000002U // Open the GPO as read only
}