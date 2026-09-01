using Microsoft.Extensions.Hosting;
using SecurityGuard.TransferGuard.Configuration;
using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.Service.Hosting;

public sealed class TransferCorrelationMaintenanceHostedService
    : BackgroundService
{
    private readonly ITransferProcessInstanceRegistry _processRegistry;
    private readonly ITransferCorrelationState _correlationState;
    private readonly TransferGuardOptions _options;

    public TransferCorrelationMaintenanceHostedService(
        ITransferProcessInstanceRegistry processRegistry,
        ITransferCorrelationState correlationState,
        TransferGuardOptions options)
    {
        _processRegistry =
            processRegistry;

        _correlationState =
            correlationState;

        _options =
            options;
    }

    protected override async Task ExecuteAsync(
        CancellationToken stoppingToken)
    {
        using var timer =
            new PeriodicTimer(
                _options.CorrelationMaintenanceInterval);

        while (await timer.WaitForNextTickAsync(
                   stoppingToken))
        {
            var stale =
                _processRegistry.PruneStale();

            foreach (var processInstance in
                     stale)
            {
                _correlationState.RemoveProcess(
                    processInstance);
            }
        }
    }
}