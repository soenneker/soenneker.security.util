[![](https://img.shields.io/nuget/v/soenneker.security.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.util/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.security.util/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.security.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.util/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.security.util/actions/workflows/codeql.yml)

# Soenneker.Security.Util

Bounded-work equality checks for secrets represented as UTF-8 bytes or characters.

## Installation

```bash
dotnet add package Soenneker.Security.Util
```

## Byte comparison

```csharp
using Soenneker.Security.Util;

bool matches = SecurityUtil.FixedCostEqualsUtf8(
    suppliedSecretUtf8,
    expectedSecretUtf8,
    paddedLength: 128);
```

The byte overload compares exactly `paddedLength` bytes of zero-padded temporary storage and includes the original byte lengths in the result. It returns `false` when either input exceeds the budget or the budget is not positive.

## Character comparison

```csharp
bool matches = SecurityUtil.FixedCostEqualsUtf8(
    suppliedSecret.AsSpan(),
    expectedSecret.AsSpan(),
    paddedLength: 128);
```

The character overload encodes both spans as UTF-8, includes their encoded lengths in the comparison, and returns `false` if either encoding exceeds the byte budget. `paddedLength` is a UTF-8 byte count, not a character count.

## Choosing a budget

Use a fixed, trusted budget large enough for every valid value in the credential class you are comparing. Do not derive it from the supplied secret, and do not expose an unbounded caller-controlled value: budgets above 256 bytes rent temporary arrays proportional to the requested size.

The comparison loop performs work based on the fixed budget rather than the location of the first mismatch. Input validation and UTF-8 encoding still depend on input length, so this API should not be described as making the entire surrounding authentication flow constant-time.

Temporary byte buffers are zeroed before return. The input spans are read-only and remain owned by the caller; this utility cannot clear them. Avoid creating immutable secret strings when byte-oriented input is available.

This is an equality primitive, not password hashing. Use a purpose-built password hashing or identity system for user passwords; use fixed-cost equality for already-protected tokens, API keys, signatures, or similar fixed-secret verification where direct equality is appropriate.
