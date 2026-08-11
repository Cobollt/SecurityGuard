using SecurityGuard.Core.Enums;

namespace SecurityGuard.Core.Models;

public sealed record SecurityRule(
    Guid Id,
    string Name,
    SecurityModuleKind Module,
    RuleDecision Decision,
    RuleScope Scope,
    string Value,
    bool Enabled,
    int Priority,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc);