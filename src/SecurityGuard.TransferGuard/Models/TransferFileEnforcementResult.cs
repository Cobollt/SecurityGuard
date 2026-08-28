namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferFileEnforcementResult(
    bool Applied,
    bool Skipped,
    string Message,
    DateTimeOffset? ExpiresAtUtc);