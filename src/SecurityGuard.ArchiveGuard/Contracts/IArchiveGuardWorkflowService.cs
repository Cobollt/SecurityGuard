using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardWorkflowService
{
    Task<ArchiveGuardWorkflowResult> ScanAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}