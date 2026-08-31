using SecurityGuard.Core.Enums;
using SecurityGuard.TransferGuard.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferManualRuleRequest(
    string Name,
    TransferActivityKind ActivityKind,
    RuleDecision Decision,
    IReadOnlyList<TransferManualRuleCondition> Conditions,
    int Priority,
    DateTimeOffset? ExpiresAtUtc);