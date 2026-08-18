using Microsoft.Extensions.Hosting;
using SecurityGuard.AlgorithmGuard.Contracts;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Service.Hosting;

public sealed class AlgorithmGuardHostedService
    : BackgroundService
{
    private readonly IAlgorithmGuardMonitor _monitor;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    public AlgorithmGuardHostedService(
        IAlgorithmGuardMonitor monitor,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor = monitor;
        _moduleRegistry = moduleRegistry;
        _auditService = auditService;
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
            _moduleRegistry.Set(
                SecurityModuleKind.AlgorithmGuard,
                ModuleOperationalState.Active,
                "Passive monitoring is active");

            await _auditService.WriteAsync(
                SecurityModuleKind.AlgorithmGuard,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "AlgorithmGuard started",
                "Passive process monitoring started",
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
                "AlgorithmGuard monitoring failed");

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