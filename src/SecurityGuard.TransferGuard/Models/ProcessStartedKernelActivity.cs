namespace SecurityGuard.TransferGuard.Models;

public sealed record ProcessStartedKernelActivity(
    TransferProcessInstanceId ProcessInstance,
    DateTimeOffset DetectedAtUtc)
    : TransferKernelActivity(
        ProcessInstance.ProcessId,
        DetectedAtUtc);