namespace RS.Schannel.Manager.API;

// Predefined Value Types.
internal enum REG : uint
{
    REG_NONE = 0U, // No value type
    REG_SZ = 1U, // Unicode nul terminated string
    REG_EXPAND_SZ = 2U, // Unicode nul terminated string (with environment variable references)
    REG_BINARY = 3U, // Free form binary
    REG_DWORD = 4U, // 32-bit number
    REG_DWORD_LITTLE_ENDIAN = 4U, // 32-bit number (same as REG_DWORD)
    REG_DWORD_BIG_ENDIAN = 5U, // 32-bit number
    REG_LINK = 6U, // Symbolic Link (unicode)
    REG_MULTI_SZ = 7U, // Multiple Unicode strings
    REG_RESOURCE_LIST = 8U, // Resource list in the resource map
    REG_FULL_RESOURCE_DESCRIPTOR = 9U, // Resource list in the hardware description
    REG_RESOURCE_REQUIREMENTS_LIST = 10U,
    REG_QWORD = 11U, // 64-bit number
    REG_QWORD_LITTLE_ENDIAN = 11U  // 64-bit number (same as REG_QWORD)
}