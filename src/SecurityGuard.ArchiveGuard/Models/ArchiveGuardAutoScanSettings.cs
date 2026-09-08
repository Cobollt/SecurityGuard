namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveGuardAutoScanSettings(
    bool Enabled,
    bool ScanUserDownloads,
    string[] AdditionalDirectories,
    int QuietPeriodMilliseconds,
    int StabilityCheckCount,
    int StabilityCheckIntervalMilliseconds,
    int ReadyTimeoutSeconds,
    int DeduplicationWindowSeconds,
    int RecoveryLookbackMinutes,
    int WorkerCount)
{
    public static ArchiveGuardAutoScanSettings Default =>
        new(
            true,
            true,
            [],
            2000,
            3,
            500,
            120,
            30,
            10,
            4);
}