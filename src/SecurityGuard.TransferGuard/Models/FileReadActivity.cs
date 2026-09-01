namespace SecurityGuard.TransferGuard.Models;

public sealed record FileReadActivity(
    int ProcessId,
    string FilePath,
    long BytesRead,
    DateTimeOffset ReadAtUtc,
    TransferFileClassification? Classification = null,
    TransferProcessInstanceId? ProcessInstance = null);