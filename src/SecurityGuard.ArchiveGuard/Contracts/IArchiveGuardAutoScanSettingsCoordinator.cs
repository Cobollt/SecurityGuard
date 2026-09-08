using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardAutoScanSettingsCoordinator
{
    Task<ArchiveGuardAutoScanRuntimeState> GetAsync(
        CancellationToken cancellationToken = default);

    Task<ArchiveGuardAutoScanRuntimeState> UpdateAsync(
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default);
}