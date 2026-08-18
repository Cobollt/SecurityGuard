using SecurityGuard.AlgorithmGuard.Enums;

namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AlgorithmEnforcementResult(
    bool Applied,
    AlgorithmEnforcementLevel Level,
    string Message);
    