using SecurityGuard.Core.Models;
using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Contracts;

public interface IScanResultRepository
{
    Task UpsertAsync(
        ScanResult result,
        CancellationToken cancellationToken = default);

    Task<ScanResult?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    Task<ScanResult?> GetLatestBySha256Async(
        string sha256,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ScanResult>> GetRecentAsync(
        int limit,
        CancellationToken cancellationToken = default);

    Task PruneAsync(
        SecurityModuleKind module,
        DateTimeOffset olderThanUtc,
        int maxEntries,
        CancellationToken cancellationToken = default);
}