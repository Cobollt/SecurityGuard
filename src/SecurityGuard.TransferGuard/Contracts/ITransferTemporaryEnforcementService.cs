using SecurityGuard.TransferGuard.Models;

namespace SecurityGuard.TransferGuard.Contracts;

public interface ITransferTemporaryEnforcementService
{
    Task<TransferTemporaryEnforcementResult> AddOrRefreshAsync(
        TransferTemporaryEnforcementRule rule,
        CancellationToken cancellationToken = default);

    Task RemoveAsync(
        Guid ruleId,
        CancellationToken cancellationToken = default);

    Task<int> RemoveBySourceRuleIdAsync(
        Guid sourceSecurityRuleId,
        CancellationToken cancellationToken = default);

    Task<int> CleanupExpiredAsync(
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default);

    Task<int> RemoveAllAsync(
        CancellationToken cancellationToken = default);
}