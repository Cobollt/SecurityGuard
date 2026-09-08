using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardWatchDirectoryProvider
{
    IReadOnlyList<string> GetDirectories(
        ArchiveGuardAutoScanSettings settings);
}