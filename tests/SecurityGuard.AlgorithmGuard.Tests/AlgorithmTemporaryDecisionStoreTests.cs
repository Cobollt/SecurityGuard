using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class AlgorithmTemporaryDecisionStoreTests
{
    [Fact]
    public void Allow_once_is_consumed_only_once()
    {
        var store =
            new AlgorithmTemporaryDecisionStore();

        store.AllowOnce(
            "HASH:ABC");

        Assert.True(
            store.TryConsumeAllowOnce(
                "HASH:ABC"));

        Assert.False(
            store.TryConsumeAllowOnce(
                "HASH:ABC"));
    }

    [Fact]
    public void Unknown_identity_is_not_allowed()
    {
        var store =
            new AlgorithmTemporaryDecisionStore();

        Assert.False(
            store.TryConsumeAllowOnce(
                "HASH:UNKNOWN"));
    }
}