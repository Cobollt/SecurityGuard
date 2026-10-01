using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAppLockerHealthService
{
    Task<AppLockerHealthSnapshot> GetHealthAsync(
        CancellationToken cancellationToken = default);

    Task<AppLockerHealthSnapshot> EnsureReadyAsync(
        CancellationToken cancellationToken = default);
}