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
    private readonly TransferGuardOptions _options;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;

    public TransferGuardHostedService(
        ITransferGuardMonitor monitor,
        IFilteringPlatformAuditPolicyService auditPolicyService,
        TransferGuardOptions options,
        IModuleRegistry moduleRegistry,
        IAuditService auditService)
    {
        _monitor =
            monitor;

        _auditPolicyService =
            auditPolicyService;

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

            if (auditState.Changed)
            {
                await _auditService.WriteAsync(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.System,
                    SecuritySeverity.Info,
                    "WFP connection auditing enabled",
                    "Filtering Platform Connection success auditing was enabled.",
                    cancellationToken:
                        stoppingToken);
            }

            _moduleRegistry.Set(
                SecurityModuleKind.TransferGuard,
                ModuleOperationalState.Active,
                "Outbound WFP monitoring is active");

            await _auditService.WriteAsync(
                SecurityModuleKind.TransferGuard,
                SecurityEventType.System,
                SecuritySeverity.Info,
                "TransferGuard started",
                "Outbound TCP and UDP connection monitoring started.",
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