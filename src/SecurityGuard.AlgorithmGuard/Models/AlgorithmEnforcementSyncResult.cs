namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AlgorithmEnforcementSyncResult(
    int AddedRules,
    int RemovedRules,
    bool Healthy,
    IReadOnlyList<string> Warnings);