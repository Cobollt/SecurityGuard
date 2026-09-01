using Microsoft.Extensions.Hosting;
using SecurityGuard.Core.Contracts;
using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.Service.Hosting;

public sealed class TransferTelemetryHealthHostedService
    : BackgroundService
{
    private readonly ITransferTelemetryHealthTracker _healthTracker;
    private readonly ITransferGuardRuntimeState _runtimeState;
    private readonly IModuleRegistry _moduleRegistry;
    private readonly IAuditService _auditService;
    private readonly TransferGuardOptions _options;

    public TransferTelemetryHealthHostedService(
        ITransferTelemetryHealthTracker healthTracker,
        ITransferGuardRuntimeState runtimeState,
        IModuleRegistry moduleRegistry,
        IAuditService auditService,
        TransferGuardOptions options)
    {
        _healthTracker =
            healthTracker;

        _runtimeState =
            runtimeState;

        _moduleRegistry =
            moduleRegistry;

        _auditService =
            auditService;

        _options =
            options;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        var previous =
            _healthTracker.GetSnapshot();

        using var timer =
            new PeriodicTimer(
                _options.TelemetryHealthInterval);

        while (await timer.WaitForNextTickAsync(
                   stoppingToken))
        {
            var current =
                _healthTracker.GetSnapshot();

            if (!_runtimeState.CurrentSettings.Enabled)
            {
                previous =
                    current;

                continue;
            }

            if (HasTelemetryLoss(
                    previous,
                    current))
            {
                _moduleRegistry.Set(
                    SecurityModuleKind.TransferGuard,
                    ModuleOperationalState.Degraded,
                    "TransferGuard telemetry loss detected");

                await _auditService.WriteAsync(
                    SecurityModuleKind.TransferGuard,
                    SecurityEventType.System,
                    SecuritySeverity.High,
                    "TransferGuard telemetry loss",
                    BuildDetails(
                        previous,
                        current),
                    cancellationToken:
                        stoppingToken);
            }

            previous =
                current;
        }
    }

    private static bool HasTelemetryLoss(
        TransferTelemetryHealthSnapshot previous,
        TransferTelemetryHealthSnapshot current)
    {
        return current.KernelActivitiesDropped >
                   previous.KernelActivitiesDropped ||
               current.WfpEventsDropped >
                   previous.WfpEventsDropped ||
               current.KernelSourceFailures >
                   previous.KernelSourceFailures ||
               current.WfpSubscriptionFailures >
                   previous.WfpSubscriptionFailures;
    }

    private static string BuildDetails(
        TransferTelemetryHealthSnapshot previous,
        TransferTelemetryHealthSnapshot current)
    {
        return string.Join(
            Environment.NewLine,
            new[]
            {
                $"Kernel dropped: {current.KernelActivitiesDropped - previous.KernelActivitiesDropped}",
                $"WFP dropped: {current.WfpEventsDropped - previous.WfpEventsDropped}",
                $"Kernel failures: {current.KernelSourceFailures - previous.KernelSourceFailures}",
                $"WFP subscription failures: {current.WfpSubscriptionFailures - previous.WfpSubscriptionFailures}",
                $"WFP parse failures: {current.WfpParseFailures - previous.WfpParseFailures}",
                $"Correlation failures: {current.CorrelationFailures - previous.CorrelationFailures}"
            });
    }
}