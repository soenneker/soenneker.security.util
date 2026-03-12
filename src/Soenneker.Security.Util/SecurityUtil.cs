using System;
using System.Buffers;
using System.Diagnostics.Contracts;
using System.Security.Cryptography;
using System.Text;

namespace Soenneker.Security.Util;

/// <summary>
/// A library for various security related utility methods
/// </summary>
public static class SecurityUtil
{
    private const int _stackLimit = 256;

    /// <summary>
    /// Fixed-cost (O(paddedLength)) comparison of two UTF-8 byte sequences.
    /// Does not allocate; caller controls the lifetime/zeroing of inputs.
    /// Returns false if either input exceeds the padded length budget.
    /// </summary>
    [Pure]
    public static bool FixedCostEqualsUtf8(ReadOnlySpan<byte> aUtf8, ReadOnlySpan<byte> bUtf8, int paddedLength = 64)
    {
        if (paddedLength <= 0 || aUtf8.Length > paddedLength || bUtf8.Length > paddedLength)
            return false; // enforce budget (acceptable policy leak)

        byte[]? ap = null, bp = null;

        Span<byte> A = paddedLength <= _stackLimit ? stackalloc byte[paddedLength] : (ap = ArrayPool<byte>.Shared.Rent(paddedLength)).AsSpan(0, paddedLength);

        Span<byte> B = paddedLength <= _stackLimit ? stackalloc byte[paddedLength] : (bp = ArrayPool<byte>.Shared.Rent(paddedLength)).AsSpan(0, paddedLength);

        A.Clear();
        B.Clear();

        aUtf8.CopyTo(A);
        bUtf8.CopyTo(B);

        int diff = aUtf8.Length ^ bUtf8.Length;
        try
        {
            // fixed-cost loop over padding
            for (int i = 0; i < paddedLength; i++)
                diff |= A[i] ^ B[i];

            return diff == 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(A);
            CryptographicOperations.ZeroMemory(B);

            if (ap is not null)
                ArrayPool<byte>.Shared.Return(ap, clearArray: false); // already zeroed

            if (bp is not null)
                ArrayPool<byte>.Shared.Return(bp, clearArray: false);
        }
    }

    [Pure]
    public static bool FixedCostEqualsUtf8(ReadOnlySpan<char> a, ReadOnlySpan<char> b, int paddedLength = 64)
    {
        // Encode both to UTF8 into pooled/stack buffers, then call the byte comparer.
        int aLen = Encoding.UTF8.GetByteCount(a);
        int bLen = Encoding.UTF8.GetByteCount(b);

        if (aLen > paddedLength || bLen > paddedLength || paddedLength <= 0)
            return false;

        byte[]? aArr = null, bArr = null;

        Span<byte> A = paddedLength <= _stackLimit ? stackalloc byte[paddedLength] : (aArr = ArrayPool<byte>.Shared.Rent(paddedLength)).AsSpan(0, paddedLength);

        Span<byte> B = paddedLength <= _stackLimit ? stackalloc byte[paddedLength] : (bArr = ArrayPool<byte>.Shared.Rent(paddedLength)).AsSpan(0, paddedLength);

        A.Clear();
        B.Clear();

        try
        {
            Encoding.UTF8.GetBytes(a, A);
            Encoding.UTF8.GetBytes(b, B);

            return FixedCostEqualsUtf8(A, B, paddedLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(A);
            CryptographicOperations.ZeroMemory(B);

            if (aArr is not null)
                ArrayPool<byte>.Shared.Return(aArr, clearArray: false);

            if (bArr is not null)
                ArrayPool<byte>.Shared.Return(bArr, clearArray: false);
        }
    }
}