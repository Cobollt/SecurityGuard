namespace SecurityGuard.Core.Models;

public sealed record SecuritySnapshot(
    IReadOnlyList<ModuleStatus> Modules,
    IReadOnlyList<SecurityEvent> RecentEvents,
    IReadOnlyList<SecurityDecisionRequest> PendingRequests,
    int QuarantineCount,
    DateTimeOffset GeneratedAtUtc);