﻿// ------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
// ------------------------------------------------------------------------------

#pragma warning disable CS1591,CS1573,CS0465,CS0649,CS8019,CS1570,CS1584,CS1658,CS0436,CS8981
using global::System;
using global::System.Diagnostics;
using global::System.Diagnostics.CodeAnalysis;
using global::System.Runtime.CompilerServices;
using global::System.Runtime.InteropServices;
using global::System.Runtime.Versioning;
using winmdroot = global::Windows.Win32;
namespace Windows.Win32
{
    // Manually add pwszCNGAlgid & pwszCNGExtraAlgid
    namespace Security.Cryptography
    {
        /// <summary>Contains information about an object identifier (OID).</summary>
        /// <remarks>
        /// <para><see href="https://docs.microsoft.com/windows/win32/api//wincrypt/ns-wincrypt-crypt_oid_info">Learn more about this API from docs.microsoft.com</see>.</para>
        /// </remarks>
        [global::System.CodeDom.Compiler.GeneratedCode("Microsoft.Windows.CsWin32", "0.2.138-beta+f3247a3e2a")]
        internal struct CRYPT_OID_INFO
        {
            /// <summary>The size, in bytes, of this structure.</summary>
            internal uint cbSize;
            /// <summary>The OID associated with this OID information.</summary>
            internal winmdroot.Foundation.PCSTR pszOID;
            /// <summary>The display name associated with an OID.</summary>
            internal winmdroot.Foundation.PCWSTR pwszName;
            /// <summary>
            /// <para>The group identifier value associated with this OID information.</para>
            /// <para>This member can be one of the following <b>dwGroupId</b> group identifiers. </para>
            /// <para>This doc was truncated.</para>
            /// <para><see href="https://docs.microsoft.com/windows/win32/api//wincrypt/ns-wincrypt-crypt_oid_info#members">Read more on docs.microsoft.com</see>.</para>
            /// </summary>
            internal uint dwGroupId;
            internal winmdroot.Security.Cryptography.CRYPT_OID_INFO._Anonymous_e__Union Anonymous;
            /// <summary>
            /// <para>Extra information used to find or register OID information. This member applies for the following values of <b>dwGroupId</b>:</para>
            /// <para></para>
            /// <para>This doc was truncated.</para>
            /// <para><see href="https://docs.microsoft.com/windows/win32/api//wincrypt/ns-wincrypt-crypt_oid_info#members">Read more on docs.microsoft.com</see>.</para>
            /// </summary>
            internal winmdroot.Security.Cryptography.CRYPT_INTEGER_BLOB ExtraInfo;

            [StructLayout(LayoutKind.Explicit)]
            [global::System.CodeDom.Compiler.GeneratedCode("Microsoft.Windows.CsWin32", "0.2.138-beta+f3247a3e2a")]
            internal partial struct _Anonymous_e__Union
            {
                [FieldOffset(0)]
                internal uint dwValue;
                [FieldOffset(0)]
                internal uint Algid;
                [FieldOffset(0)]
                internal uint dwLength;
            }

            internal nint pwszCNGAlgid;

            internal nint pwszCNGExtraAlgid;
        }
    }
}
