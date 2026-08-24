using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmEnforcementSynchronizer
{
    Task<AlgorithmEnforcementSyncResult> SynchronizeAsync(
        CancellationToken cancellationToken = default);

    Task<int> DisableManagedRulesAsync(
        CancellationToken cancellationToken = default);
}