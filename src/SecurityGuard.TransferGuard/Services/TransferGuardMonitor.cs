using SecurityGuard.TransferGuard.Contracts;

namespace SecurityGuard.TransferGuard.Services;

public sealed class TransferGuardMonitor
    : ITransferGuardMonitor
{
    private readonly ITransferConnectionMonitor _connectionMonitor;
    private readonly TransferObservationService _observationService;

    public TransferGuardMonitor(
        ITransferConnectionMonitor connectionMonitor,
        TransferObservationService observationService)
    {
        _connectionMonitor =
            connectionMonitor;

        _observationService =
            observationService;
    }

    public async Task RunAsync(
        CancellationToken cancellationToken = default)
    {
        await foreach (
            var connection in
            _connectionMonitor.WatchAsync(
                cancellationToken))
        {
            try
            {
                await _observationService.HandleAsync(
                    connection,
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