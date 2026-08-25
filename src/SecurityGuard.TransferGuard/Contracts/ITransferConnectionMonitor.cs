using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferConnectionMonitor
{
    IAsyncEnumerable<TcpConnectionSnapshot> WatchAsync(
        CancellationToken cancellationToken = default);
}