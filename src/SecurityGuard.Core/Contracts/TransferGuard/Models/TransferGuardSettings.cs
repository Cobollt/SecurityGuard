using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferGuardSettings(
    bool Enabled,
    TransferGuardMode Mode,
    TransferEnforcementFailurePolicy FailurePolicy,
    bool TrustWindowsSystemProcesses = true)
{
    public static TransferGuardSettings Default =>
        new(
            true,
            TransferGuardMode.Monitor,
            TransferEnforcementFailurePolicy.FailOpen,
            true);
}