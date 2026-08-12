using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IQuarantineRepository
{
    Task AddAsync(
        QuarantineRecord record,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<QuarantineRecord>> GetAllAsync(
        CancellationToken cancellationToken = default);

    Task<QuarantineRecord?> GetByIdAsync(
        Guid id,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        Guid id,
        CancellationToken cancellationToken = default);
}