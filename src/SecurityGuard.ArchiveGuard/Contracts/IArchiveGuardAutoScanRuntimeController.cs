using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardAutoScanRuntimeController
{
    ArchiveGuardAutoScanSettings CurrentSettings { get; }

    IReadOnlyList<string> WatchedDirectories { get; }

    Task ApplyAsync(
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default);
}