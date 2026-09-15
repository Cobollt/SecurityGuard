using SecurityGuard.AlgorithmGuard.Enums;

namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AlgorithmGuardSettings(
    bool Enabled,
    AlgorithmGuardMode Mode,
    EnforcementFailurePolicy FailurePolicy)
{
    public static AlgorithmGuardSettings Default =>
        new(
            true,
            AlgorithmGuardMode.Monitor,
            EnforcementFailurePolicy.FailOpen);
}