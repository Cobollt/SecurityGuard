namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IAlgorithmEnforcementBackendState
{
    Task<bool> UsesProcessFallbackAsync(
        CancellationToken cancellationToken = default);
}