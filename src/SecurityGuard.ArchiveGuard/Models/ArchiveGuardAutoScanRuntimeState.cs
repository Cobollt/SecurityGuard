namespace SecurityGuard.ArchiveGuard.Models;

public sealed record ArchiveGuardAutoScanRuntimeState(
    ArchiveGuardAutoScanSettings Settings,
    IReadOnlyList<string> WatchedDirectories);