using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;

namespace SecurityGuard.Service.Application;

public sealed class ArchiveGuardAutoScanSettingsCoordinator
    : IArchiveGuardAutoScanSettingsCoordinator
{
    private readonly IArchiveGuardAutoScanSettingsService _settingsService;
    private readonly IArchiveGuardAutoScanRuntimeController _runtimeController;

    public ArchiveGuardAutoScanSettingsCoordinator(
        IArchiveGuardAutoScanSettingsService settingsService,
        IArchiveGuardAutoScanRuntimeController runtimeController)
    {
        _settingsService =
            settingsService;

        _runtimeController =
            runtimeController;
    }

    public async Task<ArchiveGuardAutoScanRuntimeState> GetAsync(
        CancellationToken cancellationToken = default)
    {
        var settings =
            await _settingsService.GetAsync(
                cancellationToken);

        return new ArchiveGuardAutoScanRuntimeState(
            settings,
            _runtimeController.WatchedDirectories);
    }

    public async Task<ArchiveGuardAutoScanRuntimeState> UpdateAsync(
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var previous =
            await _settingsService.GetAsync(
                cancellationToken);

        await _settingsService.SaveAsync(
            settings,
            cancellationToken);

        try
        {
            await _runtimeController.ApplyAsync(
                settings,
                cancellationToken);
        }
        catch
        {
            await _settingsService.SaveAsync(
                previous,
                cancellationToken);

            try
            {
                await _runtimeController.ApplyAsync(
                    previous,
                    cancellationToken);
            }
            catch
            {
            }

            throw;
        }

        return new ArchiveGuardAutoScanRuntimeState(
            settings,
            _runtimeController.WatchedDirectories);
    }
}