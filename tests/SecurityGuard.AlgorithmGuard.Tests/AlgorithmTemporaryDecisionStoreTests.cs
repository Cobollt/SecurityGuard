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
            "ALG:ABC",
            DateTimeOffset.UtcNow +
            TimeSpan.FromMinutes(1));

        Assert.True(
            store.TryConsumeAllowOnce(
                "ALG:ABC"));

        Assert.False(
            store.TryConsumeAllowOnce(
                "ALG:ABC"));
    }

    [Fact]
    public void Expired_allow_once_is_rejected()
    {
        var store =
            new AlgorithmTemporaryDecisionStore();

        store.AllowOnce(
            "ALG:ABC",
            DateTimeOffset.UtcNow -
            TimeSpan.FromSeconds(1));

        Assert.False(
            store.TryConsumeAllowOnce(
                "ALG:ABC"));
    }

    [Fact]
    public void Unknown_identity_is_not_allowed()
    {
        var store =
            new AlgorithmTemporaryDecisionStore();

        Assert.False(
            store.TryConsumeAllowOnce(
                "ALG:UNKNOWN"));
    }
}