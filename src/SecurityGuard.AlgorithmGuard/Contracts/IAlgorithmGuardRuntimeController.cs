using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmGuardRuntimeController
{
    AlgorithmGuardSettings CurrentSettings { get; }

    Task ApplyAsync(
        AlgorithmGuardSettings settings,
        CancellationToken cancellationToken = default);

    Task ReportEnforcementFailureAsync(
        string message,
        CancellationToken cancellationToken = default);
}