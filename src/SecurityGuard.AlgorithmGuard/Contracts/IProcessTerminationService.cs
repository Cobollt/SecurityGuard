using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IProcessTerminationService
{
    Task<ProcessTerminationResult> TerminateAsync(
        int processId,
        string? expectedProcessName,
        CancellationToken cancellationToken = default);
}