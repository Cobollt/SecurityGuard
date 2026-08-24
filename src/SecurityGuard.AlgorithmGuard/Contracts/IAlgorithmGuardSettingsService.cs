using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmGuardSettingsService
{
    Task<AlgorithmGuardSettings> GetAsync(
        CancellationToken cancellationToken = default);

    Task SaveAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default);
}