using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmRuntimeEnforcer
{
    Task<AlgorithmRuntimeEnforcementResult> EnforceAsync(
        AlgorithmExecutionAttempt attempt,
        CancellationToken cancellationToken = default);
}