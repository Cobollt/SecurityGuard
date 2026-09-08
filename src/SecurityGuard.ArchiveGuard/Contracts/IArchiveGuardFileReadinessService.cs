using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardFileReadinessService
{
    Task<bool> WaitUntilStableAsync(
        string filePath,
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default);
}