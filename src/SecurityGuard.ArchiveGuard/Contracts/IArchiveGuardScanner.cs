using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardScanner
{
    Task<ArchiveGuardScanResult> ScanAsync(
        ArchiveScanRequest request,
        CancellationToken cancellationToken = default);
}