namespace SecurityGuard.Core.Ipc.ArchiveGuard;

public sealed record ArchiveGuardAutoScanSettingsIpcDto(
    bool Enabled,
    bool ScanUserDownloads,
    string[] AdditionalDirectories,
    string[] WatchedDirectories);

public sealed record ArchiveGuardUpdateAutoScanSettingsIpcRequest(
    bool Enabled,
    bool ScanUserDownloads,
    string[] AdditionalDirectories);