using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.ArchiveGuard.Contracts;

public interface IArchiveGuardAutoScanSettingsService
{
    Task<ArchiveGuardAutoScanSettings> GetAsync(
        CancellationToken cancellationToken = default);

    Task SaveAsync(
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default);
}