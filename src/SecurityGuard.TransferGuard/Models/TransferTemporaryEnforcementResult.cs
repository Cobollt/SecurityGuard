namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferTemporaryEnforcementResult(
    bool Applied,
    string Message,
    DateTimeOffset? ExpiresAtUtc);