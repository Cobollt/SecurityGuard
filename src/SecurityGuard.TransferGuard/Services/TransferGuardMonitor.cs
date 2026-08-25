using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferGuardMonitor
    : ITransferGuardMonitor
{
    private readonly IOutboundConnectionEventSource _eventSource;
    private readonly TransferObservationService _observationService;
    private readonly TransferPolicyService _policyService;

    public TransferGuardMonitor(
        IOutboundConnectionEventSource eventSource,
        TransferObservationService observationService,
        TransferPolicyService policyService)
    {
        _eventSource =
            eventSource;

        _observationService =
            observationService;

        _policyService =
            policyService;
    }

    public async Task RunAsync(
        CancellationToken cancellationToken = default)
    {
        await foreach (
            var connection in
            _eventSource.WatchAsync(
                cancellationToken))
        {
            try
            {
                var observation =
                    await _observationService.EnrichAsync(
                        connection,
                        cancellationToken);

                await _policyService.HandleAsync(
                    observation,
                    cancellationToken);
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch
            {
            }
        }
    }
}