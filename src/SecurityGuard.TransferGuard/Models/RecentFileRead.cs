namespace SecurityGuard.TransferGuard.Models;

public sealed record RecentFileRead(
    int ProcessId,
    string FilePath,
    long ObservedReadBytes,
    DateTimeOffset FirstReadAtUtc,
    DateTimeOffset LastReadAtUtc);