using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.Service.Hosting;

public sealed class TransferGuardHostedService
    : BackgroundService
{
    private readonly ITransferGuardMonitor _monitor;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    public TransferGuardHostedService(
        ITransferGuardMonitor monitor,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor =
            monitor;

        _moduleRegistry =
            moduleRegistry;

        _auditService =
            auditService;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        _moduleRegistry.Set(
            SecurityModuleKind.TransferGuard,
            ModuleOperationalState.Starting,
            "TransferGuard is starting");

        try
        {
            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Active,
                "Passive TCP monitoring is active");

            await _auditService.WriteAsync(
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "TransferGuard started",
                "Passive TCP endpoint monitoring started",
                cancellationToken:
                    stoppingToken);

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
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                "TransferGuard monitoring failed");

            throw;
        }
    }

    public override async Task StopAsync(
        CancellationToken cancellationToken)
    {
        _moduleRegistry.Set(
            SecurityModuleKind.TransferGuard,
            ModuleOperationalState.Disabled,
            "TransferGuard is stopped");

        await base.StopAsync(
            cancellationToken);
    }
}