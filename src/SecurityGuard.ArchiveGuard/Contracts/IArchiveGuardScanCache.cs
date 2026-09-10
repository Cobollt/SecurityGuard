using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardScanCache
{
    bool TryGet(
        ArchiveFileMetadata metadata,
        out ArchiveGuardScanResult result);

    void Store(
        ArchiveFileMetadata metadata,
        ArchiveGuardScanResult result);

    void Clear();
}