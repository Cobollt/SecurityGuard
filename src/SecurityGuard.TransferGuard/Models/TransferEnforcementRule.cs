using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferEnforcementRule(
    Guid SecurityRuleId,
    string ProgramPath,
    string RemoteAddress,
    int RemotePort,
    TransferProtocol Protocol);