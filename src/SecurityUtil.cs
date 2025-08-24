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
    /// Compares two strings in a constant-cost, timing-safe manner by encoding them as UTF-8,
    /// padding or truncating to a fixed <paramref name="paddedUtf8Length"/>, and walking all bytes
    /// without early exit.
    /// </summary>
    /// <param name="a">The first string to compare. May be <see langword="null"/>.</param>
    /// <param name="b">The second string to compare. May be <see langword="null"/>.</param>
    /// <param name="paddedUtf8Length">
    /// The exact number of UTF-8 bytes to process. Both inputs are zero-padded to this size,
    /// and any input longer than this value is treated as a mismatch.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if both strings are equal when encoded as UTF-8, zero-padded, and
    /// compared over the full <paramref name="paddedUtf8Length"/>; otherwise, <see langword="false"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This method is intended for comparing security-sensitive values such as API secrets or tokens,
    /// where both the <em>content</em> and the <em>length</em> must be protected from timing analysis.
    /// It ensures that the loop always runs for exactly <paramref name="paddedUtf8Length"/> iterations,
    /// regardless of how similar or different the inputs are.
    /// </para>
    /// <para>
    /// Usage guidance:
    /// <list type="bullet">
    /// <item><description>
    /// For secrets with a known, fixed length (e.g. 32-byte HMAC tags), set
    /// <paramref name="paddedUtf8Length"/> to that length.
    /// </description></item>
    /// <item><description>
    /// Inputs longer than <paramref name="paddedUtf8Length"/> are rejected immediately as mismatches.
    /// </description></item>
    /// <item><description>
    /// For non-secret identifiers (e.g. usernames), consider using a simpler equality
    /// check or <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
    /// when you already have equal-length byte spans.
    /// </description></item>
    /// </list>
    /// </para>
    /// </remarks>
    [Pure]
    public static bool FixedCostEqualsString(string? a, string? b, int paddedUtf8Length = 64)
    {
        if (a is null || b is null || paddedUtf8Length <= 0)
            return false;

        int aLen = Encoding.UTF8.GetByteCount(a);
        int bLen = Encoding.UTF8.GetByteCount(b);

        if (aLen > paddedUtf8Length || bLen > paddedUtf8Length)
            return false; // outside budget → definitive mismatch

        byte[]? ap = null, bp = null;
        Span<byte> A = paddedUtf8Length <= _stackLimit
            ? stackalloc byte[paddedUtf8Length]
            : (ap = ArrayPool<byte>.Shared.Rent(paddedUtf8Length)).AsSpan(0, paddedUtf8Length);

        Span<byte> B = paddedUtf8Length <= _stackLimit
            ? stackalloc byte[paddedUtf8Length]
            : (bp = ArrayPool<byte>.Shared.Rent(paddedUtf8Length)).AsSpan(0, paddedUtf8Length);

        A.Clear();
        B.Clear();

        _ = Encoding.UTF8.GetBytes(a, A[..aLen]);
        _ = Encoding.UTF8.GetBytes(b, B[..bLen]);

        int diff = aLen ^ bLen; // track length difference (still run fixed loop)
        try
        {
            for (int i = 0; i < paddedUtf8Length; i++)
                diff |= A[i] ^ B[i];

            return diff == 0;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(A);
            CryptographicOperations.ZeroMemory(B);

            if (ap is not null)
                ArrayPool<byte>.Shared.Return(ap, true);

            if (bp is not null)
                ArrayPool<byte>.Shared.Return(bp, true);
        }
    }
}