using Microsoft.Extensions.Hosting;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.AlgorithmGuard.Services;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Hosting;

public sealed class AlgorithmGuardHostedService
    : BackgroundService
{
    private readonly IAlgorithmGuardMonitor _monitor;
    private readonly AlgorithmEnforcementSynchronizer _synchronizer;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    public AlgorithmGuardHostedService(
        IAlgorithmGuardMonitor monitor,
        AlgorithmEnforcementSynchronizer synchronizer,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor =
            monitor;

        _synchronizer =
            synchronizer;

        _moduleRegistry =
            moduleRegistry;

        _auditService =
            auditService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        _moduleRegistry.Set(
            SecurityModuleKind.AlgorithmGuard,
            ModuleOperationalState.Starting,
            "AlgorithmGuard is starting");

        try
        {
            var sync =
                await _synchronizer.SynchronizeAsync(
                    stoppingToken);

            if (sync.Healthy)
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Active,
                    "Monitoring and enforcement are active");
            }
            else
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.AlgorithmGuard,
                    ModuleOperationalState.Degraded,
                    "Monitoring is active, enforcement synchronization has warnings");
            }

            await _auditService.WriteAsync(
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "AlgorithmGuard started",
                "Process monitoring started",
                cancellationToken: stoppingToken);

            await _monitor.RunAsync(
                stoppingToken);
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
        }
        catch
        {
            _moduleRegistry.Set(
                SecurityModuleKind.AlgorithmGuard,
                ModuleOperationalState.Faulted,
                "AlgorithmGuard failed");

            throw;
        }
    }

    public override async Task StopAsync(
        CancellationToken cancellationToken)
    {
        _moduleRegistry.Set(
            SecurityModuleKind.AlgorithmGuard,
            ModuleOperationalState.Disabled,
            "AlgorithmGuard is stopped");

        await base.StopAsync(
            cancellationToken);
    }
}