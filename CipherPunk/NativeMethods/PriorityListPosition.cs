// ReSharper disable InconsistentNaming
namespace Windows.Win32;

internal enum PriorityListPosition : uint
{
    CRYPT_PRIORITY_TOP = PInvoke.CRYPT_PRIORITY_TOP, // to add a function to the top of the prioritized list.
    CRYPT_PRIORITY_BOTTOM = PInvoke.CRYPT_PRIORITY_BOTTOM // to add a function to the bottom of the prioritized list.
}