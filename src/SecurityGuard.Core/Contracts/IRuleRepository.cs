using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IRuleRepository
{
    Task<IReadOnlyList<SecurityRule>> GetEnabledAsync(
        CancellationToken cancellationToken = default);

    Task UpsertAsync(
        SecurityRule rule,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        Guid id,
        CancellationToken cancellationToken = default);
}