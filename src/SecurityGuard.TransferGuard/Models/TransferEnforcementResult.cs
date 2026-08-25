namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferEnforcementResult(
    bool Applied,
    string Message);