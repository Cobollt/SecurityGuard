using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Hosting;

public sealed class SecurityGuardWorker
    : BackgroundService
{
    private readonly IModuleRegistry _moduleRegistry;

    public SecurityGuardWorker(
        IModuleRegistry moduleRegistry)
    {
        _moduleRegistry = moduleRegistry;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var coreStatus =
                _moduleRegistry.Get(
                    SecurityModuleKind.Core);

            if (coreStatus.State ==
                ModuleOperationalState.Faulted)
            {
                throw new InvalidOperationException(
                    "SecurityGuard core is faulted.");
            }

            await Task.Delay(
                TimeSpan.FromSeconds(30),
                stoppingToken);
        }
    }
}