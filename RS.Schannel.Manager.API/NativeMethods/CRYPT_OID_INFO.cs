namespace Windows.Win32
{
    using global::System.Runtime.InteropServices;
    using Windows.Win32.Foundation;
    using Windows.Win32.Security.Cryptography;

    namespace Security.Cryptography
    {
        /// <summary>Contains information about an object identifier (OID).</summary>
        /// <remarks>
        /// <para><see href="https://docs.microsoft.com/windows/win32/api//wincrypt/ns-wincrypt-crypt_oid_info">Learn more about this API from docs.microsoft.com</see>.</para>
        /// </remarks>
        internal struct CRYPT_OID_INFO
        {
            /// <summary>The size, in bytes, of this structure.</summary>
            internal uint cbSize;
            /// <summary>The OID associated with this OID information.</summary>
            internal PCSTR pszOID;
            /// <summary>The display name associated with an OID.</summary>
            internal PCWSTR pwszName;
            /// <summary>
            /// <para>The group identifier value associated with this OID information.</para>
            /// <para>This member can be one of the following <b>dwGroupId</b> group identifiers. </para>
            /// <para>This doc was truncated.</para>
            /// <para><see href="https://docs.microsoft.com/windows/win32/api//wincrypt/ns-wincrypt-crypt_oid_info#members">Read more on docs.microsoft.com</see>.</para>
            /// </summary>
            internal uint dwGroupId;
            internal CRYPT_OID_INFO._Anonymous_e__Union Anonymous;
            /// <summary>
            /// <para>Extra information used to find or register OID information. This member applies for the following values of <b>dwGroupId</b>:</para>
            /// <para></para>
            /// <para>This doc was truncated.</para>
            /// <para><see href="https://docs.microsoft.com/windows/win32/api//wincrypt/ns-wincrypt-crypt_oid_info#members">Read more on docs.microsoft.com</see>.</para>
            /// </summary>
            internal CRYPTOAPI_BLOB ExtraInfo;

            [StructLayout(LayoutKind.Explicit)]
            internal partial struct _Anonymous_e__Union
            {
                [FieldOffset(0)]
                internal uint dwValue;
                [FieldOffset(0)]
                internal uint Algid;
                [FieldOffset(0)]
                internal uint dwLength;
            }

            internal IntPtr pwszCNGAlgid;

            internal IntPtr pwszCNGExtraAlgid;
        }
    }
}