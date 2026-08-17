using SecurityGuard.Core.Enums;
using SecurityGuard.Core.Services;
using SecurityGuard.Service.Hosting;

namespace SecurityGuard.Service.Tests;

public sealed class SecurityGuardWorkerTests
{
    [Fact]
    public async Task Worker_stops_when_cancelled()
    {
        var registry =
            new ModuleRegistry();

        registry.Set(
            SecurityModuleKind.Core,
            ModuleOperationalState.Active,
            "Ready");

        var worker =
            new SecurityGuardWorker(registry);

        using var cancellation =
            new CancellationTokenSource();

        var execution =
            worker.StartAsync(
                cancellation.Token);

        await cancellation.CancelAsync();

        await worker.StopAsync(
            CancellationToken.None);

        await execution;

        Assert.Equal(
            ModuleOperationalState.Active,
            registry.Get(
                SecurityModuleKind.Core).State);
    }
}