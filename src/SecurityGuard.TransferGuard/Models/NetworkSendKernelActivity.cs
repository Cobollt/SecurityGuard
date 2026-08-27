namespace SecurityGuard.TransferGuard.Models;

public sealed record NetworkSendKernelActivity(
    NetworkSendActivity Activity)
    : TransferKernelActivity(
        Activity.ProcessId,
        Activity.SentAtUtc);