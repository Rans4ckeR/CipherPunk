﻿// ------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
// ------------------------------------------------------------------------------

#pragma warning disable CS1591,CS1573,CS0465,CS0649,CS8019,CS1570,CS1584,CS1658,CS0436
namespace RS.Schannel.Manager.API;

public enum ALG_CLASS : uint
{
    ALG_CLASS_ANY = 0,
    ALG_CLASS_SIGNATURE = 1 << 13,
    ALG_CLASS_MSG_ENCRYPT = 2 << 13,
    ALG_CLASS_DATA_ENCRYPT = 3 << 13,
    ALG_CLASS_HASH = 4 << 13,
    ALG_CLASS_KEY_EXCHANGE = 5 << 13,
    ALG_CLASS_ALL = 7 << 13
}