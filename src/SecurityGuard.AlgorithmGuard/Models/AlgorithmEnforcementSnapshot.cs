namespace SecurityGuard.AlgorithmGuard.Models;

public sealed record AlgorithmEnforcementSnapshot(
    IReadOnlySet<Guid> LocalManagedRuleIds,
    IReadOnlySet<Guid> EffectiveManagedRuleIds,
    bool ManagedBaselinePresent,
    bool UnmanagedScriptRulesPresent);