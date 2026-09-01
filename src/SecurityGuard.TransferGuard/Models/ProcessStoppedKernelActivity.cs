namespace SecurityGuard.TransferGuard.Models;

public sealed record ProcessStoppedKernelActivity(
    TransferProcessInstanceId ProcessInstance,
    DateTimeOffset DetectedAtUtc)
    : TransferKernelActivity(
        ProcessInstance.ProcessId,
        DetectedAtUtc);