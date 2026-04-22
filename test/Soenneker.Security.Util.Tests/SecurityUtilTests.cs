using Soenneker.Tests.HostedUnit;

namespace Soenneker.Security.Util.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class SecurityUtilTests : HostedUnitTest
{
    public SecurityUtilTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {

    }
}
