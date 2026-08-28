using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferTemporaryEnforcementRule(
    Guid Id,
    string ProgramPath,
    string RemoteAddress,
    int RemotePort,
    TransferProtocol Protocol,
    DateTimeOffset ExpiresAtUtc);