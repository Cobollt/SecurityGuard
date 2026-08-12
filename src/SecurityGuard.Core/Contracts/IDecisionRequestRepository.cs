using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IDecisionRequestRepository
{
    Task AddAsync(
        SecurityDecisionRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SecurityDecisionRequest>> GetPendingAsync(
        CancellationToken cancellationToken = default);

    Task<SecurityDecisionRequest?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(
        Guid id,
        CancellationToken cancellationToken = default);
}