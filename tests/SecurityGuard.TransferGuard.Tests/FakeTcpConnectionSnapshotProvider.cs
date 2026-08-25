using SecurityGuard.TransferGuard.Contracts;
using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Tests;

internal sealed class FakeTcpConnectionSnapshotProvider
    : ITcpConnectionSnapshotProvider
{
    private readonly Queue<IReadOnlyList<TcpConnectionSnapshot>> _snapshots;

    public FakeTcpConnectionSnapshotProvider(
        params IReadOnlyList<TcpConnectionSnapshot>[] snapshots)
    {
        _snapshots =
            new Queue<IReadOnlyList<TcpConnectionSnapshot>>(
                snapshots);
    }

    public Task<IReadOnlyList<TcpConnectionSnapshot>> GetAsync(
        CancellationToken cancellationToken = default)
    {
        if (_snapshots.Count == 0)
        {
            return Task.FromResult<
                IReadOnlyList<TcpConnectionSnapshot>>(
                []);
        }

        return Task.FromResult(
            _snapshots.Dequeue());
    }
}