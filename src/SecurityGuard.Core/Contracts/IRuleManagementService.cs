using SecurityGuard.Core.Models;

namespace SecurityGuard.Core.Contracts;

public interface IRuleManagementService
{
    Task<IReadOnlyList<SecurityRule>> GetAllAsync(
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default);
}