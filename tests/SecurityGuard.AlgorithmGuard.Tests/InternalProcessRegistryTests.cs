using SecurityGuard.AlgorithmGuard.Services;

namespace SecurityGuard.AlgorithmGuard.Tests;

public sealed class InternalProcessRegistryTests
{
    [Fact]
    public void Registered_process_is_consumed_once()
    {
        var registry =
            new InternalProcessRegistry();

        registry.Register(
            1234);

        Assert.True(
            registry.TryConsume(
                1234));

        Assert.False(
            registry.TryConsume(
                1234));
    }

    [Fact]
    public void Unknown_process_is_not_internal()
    {
        var registry =
            new InternalProcessRegistry();

        Assert.False(
            registry.TryConsume(
                9999));
    }
}