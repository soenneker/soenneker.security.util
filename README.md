[![](https://img.shields.io/nuget/v/soenneker.security.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.util/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.security.util/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.security.util.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.security.util/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.security.util/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.security.util/actions/workflows/codeql.yml)

# Soenneker.Security.Util

A library for various security related utility methods.

## Install

```bash
dotnet add package Soenneker.Security.Util
```

## Quick start

```csharp
using Soenneker.Security.Util;

var result = SecurityUtil.FixedCostEqualsUtf8(/* supply aUtf8 */ default!, /* supply bUtf8 */ default!);
```

Compares two character sequences as padded UTF-8 data using fixed-cost work.

## What you get

- `SecurityUtil` — A library for various security related utility methods.

## API at a glance

| API | What it does | Result / important behavior |
| --- | --- | --- |
| `SecurityUtil.FixedCostEqualsUtf8(aUtf8, bUtf8, paddedLength)` | Compares two character sequences as padded UTF-8 data using fixed-cost work. | true if fixed-cost (O(paddedLength)) comparison of two UTF-8 byte sequences. Does not allocate; caller controls the lifetime/zeroing of inputs. Returns false if either input exceeds the padded length budget; otherwise, false. |
| `SecurityUtil.FixedCostEqualsUtf8(a, b, paddedLength)` | Compares two character sequences as padded UTF-8 data using fixed-cost work. | true if both UTF-8 representations are equal; otherwise, false. |
