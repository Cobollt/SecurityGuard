namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferEnforcementSnapshot(
    IReadOnlySet<Guid> PersistentManagedRuleIds,
    IReadOnlySet<Guid> ActiveManagedRuleIds);