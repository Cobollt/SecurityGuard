namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferEnforcementSyncResult(
    int AddedRules,
    int RemovedRules,
    bool Healthy,
    IReadOnlyList<string> Warnings);