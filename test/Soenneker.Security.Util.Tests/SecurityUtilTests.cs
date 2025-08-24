using Soenneker.Tests.FixturedUnit;
using Xunit;

namespace Soenneker.Security.Util.Tests;

[Collection("Collection")]
public sealed class SecurityUtilTests : FixturedUnitTest
{
    public SecurityUtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
    }

    [Fact]
    public void Default()
    {

    }
}
