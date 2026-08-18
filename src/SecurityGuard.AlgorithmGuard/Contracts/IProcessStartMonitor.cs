using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IProcessStartMonitor
{
    IAsyncEnumerable<ProcessStartSignal> WatchAsync(
        CancellationToken cancellationToken = default);
}