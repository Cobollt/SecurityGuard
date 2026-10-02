namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AlgorithmRuntimeEnforcementResult(
    bool Required,
    bool Terminated,
    string Message);