using SecurityGuard.ArchiveGuard.Enums;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveRecursiveScanner
{
    bool Supports(
        DetectedFileType fileType);

    Task<ArchiveRecursiveScanResult> ScanAsync(
        string filePath,
        DetectedFileType fileType,
        CancellationToken cancellationToken = default);
}