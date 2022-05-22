namespace Windows.Win32;

public enum PriorityListPosition : uint
{
#pragma warning disable CA1707 // Identifiers should not contain underscores
    CRYPT_PRIORITY_TOP = 0U, // to add a function to the top of the prioritized list.

    CRYPT_PRIORITY_BOTTOM = 0xFFFFFFFF // to add a function to the bottom of the prioritized list.
#pragma warning restore CA1707 // Identifiers should not contain underscores
}