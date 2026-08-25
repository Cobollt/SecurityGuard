using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface IOutboundConnectionEventSource
{
    IAsyncEnumerable<FilteringPlatformConnectionEvent> WatchAsync(
        CancellationToken cancellationToken = default);
}