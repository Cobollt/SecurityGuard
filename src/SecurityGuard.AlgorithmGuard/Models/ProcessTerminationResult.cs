namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record ProcessTerminationResult(
    bool Terminated,
    string Message);