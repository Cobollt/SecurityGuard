using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.Service.Hosting;

public sealed class TransferGuardHostedService
    : BackgroundService
{
    private readonly ITransferGuardMonitor _monitor;
    private readonly IFilteringPlatformAuditPolicyService _auditPolicyService;
    private readonly ITransferEnforcementSynchronizer _synchronizer;
    private readonly TransferGuardOptions _options;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    public TransferGuardHostedService(
        ITransferGuardMonitor monitor,
        IFilteringPlatformAuditPolicyService auditPolicyService,
        ITransferEnforcementSynchronizer synchronizer,
        TransferGuardOptions options,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor =
            monitor;

        _auditPolicyService =
            auditPolicyService;

        _synchronizer =
            synchronizer;

        _options =
            options;

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
            var auditState =
                _options.AutoEnableFilteringPlatformAudit
                    ? await _auditPolicyService.EnsureSuccessEnabledAsync(
                        stoppingToken)
                    : await _auditPolicyService.GetAsync(
                        stoppingToken);

            if (!auditState.SuccessEnabled)
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Faulted,
                    "Filtering Platform Connection auditing is disabled");

                return;
            }

            var synchronization =
                await _synchronizer.SynchronizeAsync(
                    stoppingToken);

            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                synchronization.Healthy
                    ? ModuleOperationalState.Active
                    : ModuleOperationalState.Degraded,
                synchronization.Healthy
                    ? "Outbound monitoring and Firewall enforcement are active"
                    : "Outbound monitoring is active; Firewall synchronization has warnings");

            await _auditService.WriteAsync(
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                synchronization.Healthy
                    ? SecuritySeverity.Info
                    : SecuritySeverity.Medium,
                "TransferGuard started",
                synchronization.Healthy
                    ? "Outbound TCP/UDP monitoring and Windows Firewall enforcement started."
                    : "Outbound monitoring started with enforcement warnings.",
                cancellationToken:
                    stoppingToken);

            await _monitor.RunAsync(
                stoppingToken);
        }
        catch (OperationCanceledException)
            when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Faulted,
                exception.Message);

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