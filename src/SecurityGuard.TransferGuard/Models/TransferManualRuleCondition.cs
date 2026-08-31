using SecurityGuard.Core.Enums;

namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferManualRuleCondition(
    RuleScope Scope,
    string Value);