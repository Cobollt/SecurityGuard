namespace SecurityGuard.TransferGuard.Models;

public sealed record FileReadKernelActivity(
    FileReadActivity Activity)
    : TransferKernelActivity(
        Activity.ProcessId,
        Activity.ReadAtUtc);