﻿// ------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
// ------------------------------------------------------------------------------

namespace Windows.Win32;

using global::System.Runtime.InteropServices;

internal struct NCRYPT_SSL_CIPHER_SUITE
{
    internal SslProviderProtocolId dwProtocol;

    internal SslProviderCipherSuiteId dwCipherSuite;

    internal SslProviderCipherSuiteId dwBaseCipherSuite;

    internal __char_64 szCipherSuite;

    internal __char_64 szCipher;

    internal uint dwCipherLen;

    internal uint dwCipherBlockLen; // in bytes

    internal __char_64 szHash;

    internal uint dwHashLen;

    internal __char_64 szExchange;

    internal uint dwMinExchangeLen;

    internal uint dwMaxExchangeLen;

    internal __char_64 szCertificate;

    internal SslProviderKeyTypeId dwKeyType;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct __char_64
    {
        internal char _0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63;

        /// <summary>Always <c>64</c>.</summary>
        internal readonly int Length => 64;

        /// <summary>
        /// Gets a ref to an individual element of the inline array.
        /// ⚠ Important ⚠: When this struct is on the stack, do not let the returned reference outlive the stack frame that defines it.
        /// </summary>
        internal ref char this[int index] => ref AsSpan()[index];

        /// <summary>
        /// Gets this inline array as a span.
        /// </summary>
        /// <remarks>
        /// ⚠ Important ⚠: When this struct is on the stack, do not let the returned span outlive the stack frame that defines it.
        /// </remarks>
        internal Span<char> AsSpan() => MemoryMarshal.CreateSpan(ref _0, 64);

        internal unsafe readonly void CopyTo(Span<char> target, int length = 64)
        {
            if (length > 64) throw new ArgumentOutOfRangeException("length");
            fixed (char* p0 = &_0)
                for (int i = 0;
                i < length;
                i++) target[i] = p0[i];
        }

        internal readonly char[] ToArray(int length = 64)
        {
            if (length > 64) throw new ArgumentOutOfRangeException("length");
            char[] target = new char[length];
            CopyTo(target, length);
            return target;
        }

        internal unsafe readonly bool Equals(ReadOnlySpan<char> value)
        {
            fixed (char* p0 = &_0)
            {
                int commonLength = Math.Min(value.Length, 64);
                for (int i = 0;
                i < commonLength;
                i++) if (p0[i] != value[i]) return false;
                for (int i = commonLength;
                i < 64;
                i++) if (p0[i] != default(char)) return false;
            }
            return true;
        }

        internal readonly bool Equals(string value) => Equals(value.AsSpan());

        /// <summary>
        /// Copies the fixed array to a new string up to the specified length regardless of whether there are null terminating characters.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when <paramref name="length"/> is less than <c>0</c> or greater than <see cref="Length"/>.
        /// </exception>
        internal unsafe readonly string ToString(int length)
        {
            if (length < 0 || length > Length) throw new ArgumentOutOfRangeException(nameof(length), length, "Length must be between 0 and the fixed array length.");
            fixed (char* p0 = &_0)
                return new string(p0, 0, length);
        }

        /// <summary>
        /// Copies the fixed array to a new string, stopping before the first null terminator character or at the end of the fixed array (whichever is shorter).
        /// </summary>
        public override readonly unsafe string ToString()
        {
            int length;
            fixed (char* p = &_0)
            {
                char* pLastExclusive = p + Length;
                char* pCh = p;
                for (;
                pCh < pLastExclusive && *pCh != '\0';
                pCh++) ;
                length = checked((int)(pCh - p));
            }
            return ToString(length);
        }
        public static implicit operator __char_64(string value) => value.AsSpan();
        public static implicit operator __char_64(ReadOnlySpan<char> value)
        {
            __char_64 result = default(__char_64);
            value.CopyTo(result.AsSpan());
            return result;
        }
    }
}