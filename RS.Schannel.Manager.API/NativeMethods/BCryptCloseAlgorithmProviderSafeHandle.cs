﻿// ------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
// ------------------------------------------------------------------------------

#pragma warning disable CS1591,CS1573,CS0465,CS0649,CS8019,CS1570,CS1584,CS1658,CS0436,CS8981
namespace Windows.Win32
{
    using global::System;
    using global::System.Diagnostics;
    using global::System.Runtime.CompilerServices;
    using global::System.Runtime.InteropServices;
    using global::System.Runtime.Versioning;
    using winmdroot = global::Windows.Win32;


    /// <summary>
    /// Represents a Win32 handle that can be closed with <see cref="PInvoke.BCryptCloseAlgorithmProvider"/>.
    /// </summary>
    internal class BCryptCloseAlgorithmProviderSafeHandle
        : SafeHandle
    {
        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(0L);
        internal BCryptCloseAlgorithmProviderSafeHandle() : base(INVALID_HANDLE_VALUE, true)
        {
        }
        internal BCryptCloseAlgorithmProviderSafeHandle(IntPtr preexistingHandle, bool ownsHandle = true) : base(INVALID_HANDLE_VALUE, ownsHandle)
        {
            this.SetHandle(preexistingHandle);
        }

        public override bool IsInvalid => this.handle.ToInt64() == 0L;

        protected override bool ReleaseHandle() => PInvoke.BCryptCloseAlgorithmProvider((winmdroot.Security.Cryptography.BCRYPT_ALG_HANDLE)this.handle, 0U) == winmdroot.Foundation.NTSTATUS.STATUS_SUCCESS;
    }
}
