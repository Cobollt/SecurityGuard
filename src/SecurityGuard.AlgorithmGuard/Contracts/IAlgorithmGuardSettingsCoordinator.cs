using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmGuardSettingsCoordinator
{
    Task<AlgorithmGuardSettings> GetAsync(
        CancellationToken cancellationToken = default);

    Task UpdateAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default);
}