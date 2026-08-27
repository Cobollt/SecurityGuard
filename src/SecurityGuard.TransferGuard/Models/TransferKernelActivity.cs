namespace SecurityGuard.TransferGuard.Models;

public abstract record TransferKernelActivity(
    int ProcessId,
    DateTimeOffset OccurredAtUtc);