using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IProcessAncestryProvider
{
    Task<IReadOnlyList<ProcessAncestryEntry>> GetAsync(
        ProcessMetadata process,
        CancellationToken cancellationToken = default);
}