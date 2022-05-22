﻿namespace Windows.Win32;

[Flags]
internal enum IconInfo : uint
{
    SHGSI_ICONLOCATION = 0U, // you always get the icon location
    SHGSI_ICON = 0x000000100, // get icon
    SHGSI_SYSICONINDEX = 0x000004000, // get system icon index
    SHGSI_LINKOVERLAY = 0x000008000, // put a link overlay on icon
    SHGSI_SELECTED = 0x000010000, // show icon in selected state
    SHGSI_LARGEICON = SHGSI_ICONLOCATION, // get large icon
    SHGSI_SMALLICON = 0x000000001, // get small icon
    SHGSI_SHELLICONSIZE = 0x000000004 // get shell size icon
}