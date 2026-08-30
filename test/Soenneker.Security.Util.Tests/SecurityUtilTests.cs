using System.Threading.Tasks;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.Security.Util.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class SecurityUtilTests : HostedUnitTest
{
    public SecurityUtilTests(Host host) : base(host)
    {
    }

    [Test]
    public async Task Character_comparison_includes_encoded_length()
    {
        bool equal = SecurityUtil.FixedCostEqualsUtf8("secret", "secret\0");

        await Assert.That(equal).IsFalse();
    }

    [Test]
    public async Task Equal_unicode_values_match()
    {
        bool equal = SecurityUtil.FixedCostEqualsUtf8("påssword", "påssword");

        await Assert.That(equal).IsTrue();
    }

    [Test]
    public async Task Values_over_budget_do_not_match()
    {
        bool equal = SecurityUtil.FixedCostEqualsUtf8("12345", "12345", paddedLength: 4);

        await Assert.That(equal).IsFalse();
    }
}
