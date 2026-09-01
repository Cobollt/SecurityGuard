namespace SecurityGuard.TransferGuard.Models;

public sealed record TransferTelemetryHealthSnapshot(
    long KernelActivitiesDropped,
    long WfpEventsDropped,
    long KernelSourceFailures,
    long WfpSubscriptionFailures,
    long WfpParseFailures,
    long CorrelationFailures,
    DateTimeOffset? LastProblemAtUtc);