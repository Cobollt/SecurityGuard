using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.Service.Hosting;

public sealed class TransferTemporaryEnforcementMaintenanceHostedService
    : BackgroundService
{
    private readonly ITransferTemporaryEnforcementService _enforcementService;
    private readonly TransferGuardOptions _options;
    private readonly IAuditService _auditService;
    private readonly IModuleRegistry _moduleRegistry;

    public TransferTemporaryEnforcementMaintenanceHostedService(
        ITransferTemporaryEnforcementService enforcementService,
        TransferGuardOptions options,
        IAuditService auditService,
        IModuleRegistry moduleRegistry)
    {
        _enforcementService =
            enforcementService;

        _options =
            options;

        _auditService =
            auditService;

        _moduleRegistry =
            moduleRegistry;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        await CleanupAsync(
            stoppingToken);

        using var timer =
            new PeriodicTimer(
                _options.TemporaryEnforcementCleanupInterval);

        while (await timer.WaitForNextTickAsync(
                   stoppingToken))
        {
            await CleanupAsync(
                stoppingToken);
        }
    }

    private async Task CleanupAsync(
        CancellationToken cancellationToken)
    {
        try
        {
            var removed =
                await _enforcementService.CleanupExpiredAsync(
                    DateTimeOffset.UtcNow,
                    cancellationToken);

            if (removed <= 0)
            {
                return;
            }

            await _auditService.WriteAsync(
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "Temporary Firewall rules expired",
                $"Removed temporary TransferGuard rules: {removed}",
                cancellationToken:
                    cancellationToken);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Degraded,
                "Temporary Firewall cleanup failed");

            try
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.System,
                    SecuritySeverity.High,
                    "Temporary Firewall cleanup failed",
                    exception.Message,
                    cancellationToken:
                        CancellationToken.None);
            }
            catch
            {
            }
        }
    }
}