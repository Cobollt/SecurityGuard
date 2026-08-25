using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITcpConnectionSnapshotProvider
{
    Task<IReadOnlyList<TcpConnectionSnapshot>> GetAsync(
        CancellationToken cancellationToken = default);
}