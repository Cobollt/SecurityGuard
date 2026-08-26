using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferGuardSettings(
    bool Enabled,
    TransferGuardMode Mode,
    TransferEnforcementFailurePolicy FailurePolicy)
{
    public static TransferGuardSettings Default =>
        new(
            true,
            TransferGuardMode.Monitor,
            TransferEnforcementFailurePolicy.FailOpen);
}