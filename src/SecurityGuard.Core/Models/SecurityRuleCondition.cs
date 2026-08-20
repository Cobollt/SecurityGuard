using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record SecurityRuleCondition(
    RuleScope Scope,
    string Value);