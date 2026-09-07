using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IThreatHashRepository
{
    Task<ThreatHashEntry?> GetBySha256Async(
        string sha256,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<ThreatHashEntry>> GetAllAsync(
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        ThreatHashEntry entry,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string sha256,
        CancellationToken cancellationToken = default);
}