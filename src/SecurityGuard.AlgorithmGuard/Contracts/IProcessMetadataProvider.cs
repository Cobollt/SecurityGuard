using SecurityGuard.AlgorithmGuard.Models;

namespace SecurityGuard.AlgorithmGuard.Contracts;

public interface IProcessMetadataProvider
{
    Task<ProcessMetadata?> GetAsync(
        int processId,
        CancellationToken cancellationToken = default);
}