using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveRecursiveScanner
{
    Task<ArchiveRecursiveScanResult> ScanZipAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}