using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface IFileReadActivitySource
{
    IAsyncEnumerable<FileReadActivity> WatchAsync(
        CancellationToken cancellationToken = default);
}