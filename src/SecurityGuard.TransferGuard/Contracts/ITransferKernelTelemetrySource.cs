using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferKernelTelemetrySource
{
    IAsyncEnumerable<TransferKernelActivity> WatchAsync(
        CancellationToken cancellationToken = default);
}