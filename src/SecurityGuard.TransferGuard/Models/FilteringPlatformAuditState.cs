namespace SecurityGuard.TransferGuard.Models;

public sealed record FilteringPlatformAuditState(
    bool SuccessEnabled,
    bool FailureEnabled,
    bool Changed);