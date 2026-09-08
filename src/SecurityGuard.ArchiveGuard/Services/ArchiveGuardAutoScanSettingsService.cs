using System.Text.Json;
using SecurityGuard.ArchiveGuard.Contracts;
using SecurityGuard.ArchiveGuard.Models;
using SecurityGuard.Core.Contracts;

namespace SecurityGuard.ArchiveGuard.Services;

public sealed class ArchiveGuardAutoScanSettingsService
    : IArchiveGuardAutoScanSettingsService
{
    private const string SettingsKey =
        "ArchiveGuard.AutoScan.Settings";

    private readonly ISettingsRepository _settingsRepository;

    public ArchiveGuardAutoScanSettingsService(
        ISettingsRepository settingsRepository)
    {
        _settingsRepository =
            settingsRepository;
    }

    public async Task<ArchiveGuardAutoScanSettings> GetAsync(
        CancellationToken cancellationToken = default)
    {
        var value =
            await _settingsRepository.GetAsync(
                SettingsKey,
                cancellationToken);

        if (string.IsNullOrWhiteSpace(
                value))
        {
            return ArchiveGuardAutoScanSettings.Default;
        }

        try
        {
            var settings =
                JsonSerializer.Deserialize<
                    ArchiveGuardAutoScanSettings>(
                        value);

            return settings is null
                ? ArchiveGuardAutoScanSettings.Default
                : Normalize(
                    settings);
        }
        catch (JsonException)
        {
            return ArchiveGuardAutoScanSettings.Default;
        }
    }

    public async Task SaveAsync(
        ArchiveGuardAutoScanSettings settings,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(
            settings);

        var normalized =
            Normalize(
                settings);

        await _settingsRepository.SetAsync(
            SettingsKey,
            JsonSerializer.Serialize(
                normalized),
            cancellationToken);
    }

    private static ArchiveGuardAutoScanSettings Normalize(
        ArchiveGuardAutoScanSettings settings)
    {
        var directories =
            settings.AdditionalDirectories
                .Where(
                    value =>
                        !string.IsNullOrWhiteSpace(
                            value))
                .Select(
                    value =>
                        value.Trim())
                .Distinct(
                    StringComparer.OrdinalIgnoreCase)
                .ToArray();

        return settings with
        {
            AdditionalDirectories =
                directories,

            QuietPeriodMilliseconds =
                Math.Clamp(
                    settings.QuietPeriodMilliseconds,
                    500,
                    30_000),

            StabilityCheckCount =
                Math.Clamp(
                    settings.StabilityCheckCount,
                    1,
                    10),

            StabilityCheckIntervalMilliseconds =
                Math.Clamp(
                    settings.StabilityCheckIntervalMilliseconds,
                    100,
                    10_000),

            ReadyTimeoutSeconds =
                Math.Clamp(
                    settings.ReadyTimeoutSeconds,
                    10,
                    1800),

            DeduplicationWindowSeconds =
                Math.Clamp(
                    settings.DeduplicationWindowSeconds,
                    1,
                    600),

            RecoveryLookbackMinutes =
                Math.Clamp(
                    settings.RecoveryLookbackMinutes,
                    1,
                    1440),

            WorkerCount =
                Math.Clamp(
                    settings.WorkerCount,
                    1,
                    8)
        };
    }
}