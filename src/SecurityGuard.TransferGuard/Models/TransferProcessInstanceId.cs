namespace SecurityGuard.TransferGuard.Models;

public readonly record struct TransferProcessInstanceId(
    int ProcessId,
    DateTimeOffset StartedAtUtc);